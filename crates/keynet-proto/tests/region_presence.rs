use keynet_proto::{
    RegionCarrier, RegionGone, RegionGoneReason, RegionMarks, RegionOwner, RegionPresence,
    RegionPresenceCapacity, RegionPresenceChannels, RegionPresenceEffect, RegionPresenceEvent,
    RegionPresenceInput, RegionPresenceOrigin, RegionPresenceOriginState, RegionPresenceRecord,
    RegionPresenceSession, RegionPresenceStream, RegionPresenceTable, RegionSnapshot,
    RegionSnapshotCompletionInput, RegionSnapshotCutCommitment, RegionSnapshotDisposition,
    RegionSnapshotDurableBatchAcknowledgment, RegionSnapshotDurableBatchAcknowledgmentInput,
    RegionSnapshotDurableCutReceipt, RegionSnapshotOwnerIndexOutcome,
    RegionSnapshotOwnerValidation, RegionSnapshotOwnerValidationInput, RegionSnapshotStage,
    RegionSnapshotStagingCapacity, RegionSnapshotStagingInput, RegionSnapshotStagingTable,
    acknowledge_region_snapshot_durable_batch,
    begin_region_snapshot_control as begin_region_snapshot_control_raw,
    complete_region_snapshot as complete_region_snapshot_raw, decide_region_presence,
    derive_slot_id, interrupt_region_snapshot as interrupt_region_snapshot_raw,
    stage_region_snapshot as stage_region_snapshot_raw, validate_region_snapshot_owners,
};
use std::{collections::BTreeMap, fs, path::PathBuf};

mod snapshot_test_support;

const ROOT: &str = "tests/fixtures/keynet-v1";

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(ROOT)
        .join("region_presence.vec")
}

fn fixture_expect(case_name: &str, expected: &str) -> Result<(), String> {
    let text = fs::read_to_string(fixture_path()).map_err(|error| error.to_string())?;
    let mut cases = BTreeMap::new();
    for block in text.split("\n\n").filter(|block| !block.trim().is_empty()) {
        let mut fields = BTreeMap::new();
        for line in block.lines().filter(|line| !line.starts_with('#')) {
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| "invalid region presence vector line".to_owned())?;
            if fields.insert(key, value).is_some() {
                return Err(format!("duplicate region presence vector field: {key}"));
            }
        }
        if fields.len() != 2 {
            return Err("region presence vector must have exactly two fields".to_owned());
        }
        let name = fields
            .get("case")
            .ok_or_else(|| "region presence vector lacks case".to_owned())?;
        let value = fields
            .get("expected")
            .ok_or_else(|| "region presence vector lacks expected".to_owned())?;
        if cases
            .insert((*name).to_owned(), (*value).to_owned())
            .is_some()
        {
            return Err(format!("duplicate region presence vector case: {name}"));
        }
    }
    if cases.get(case_name).is_none_or(|actual| actual != expected) {
        return Err(format!("unexpected sealed expectation for {case_name}"));
    }
    Ok(())
}

fn origin(member_id: u8, boot_epoch: u64) -> RegionPresenceOrigin {
    RegionPresenceOrigin {
        member_id,
        boot_epoch,
    }
}

fn presence_for(
    origin: RegionPresenceOrigin,
    identity_byte: u8,
    slot_byte: u8,
    generation: u64,
    incarnation: u64,
    revision: u64,
) -> RegionPresence {
    RegionPresence {
        slot: [slot_byte; 16],
        network_id: [0x11; 32],
        identity: [identity_byte; 32],
        generation,
        incarnation,
        carrier: RegionCarrier::Udp,
        boot_epoch: origin.boot_epoch,
        revision,
    }
}

fn record(
    origin: RegionPresenceOrigin,
    presence: RegionPresence,
    grace_cached: bool,
) -> RegionPresenceRecord {
    RegionPresenceRecord {
        session: RegionPresenceSession { origin, presence },
        eligible: true,
        grace_cached,
    }
}

fn marks(identity_byte: u8, generation: u64, incarnation_high_water: u64) -> RegionMarks {
    RegionMarks {
        network_id: [0x11; 32],
        identity: [identity_byte; 32],
        committed_generation: generation,
        committed_key: [0x44; 32],
        conflicted: false,
        revoked_through: None,
        incarnation_high_water,
    }
}

fn state(origin: RegionPresenceOrigin, revision_high_water: u64) -> RegionPresenceOriginState {
    RegionPresenceOriginState {
        origin,
        revision_high_water,
        snapshot_required: false,
    }
}

fn table(
    entries: Vec<RegionPresenceRecord>,
    origins: Vec<RegionPresenceOriginState>,
) -> RegionPresenceTable {
    RegionPresenceTable { entries, origins }
}

fn channels(origins: &[RegionPresenceOrigin]) -> Vec<RegionPresenceChannels> {
    origins
        .iter()
        .copied()
        .map(|origin| RegionPresenceChannels {
            origin,
            control_up: true,
            data_up: true,
        })
        .collect()
}

fn input<'a>(
    stream: RegionPresenceStream,
    durable_marks: &'a [RegionMarks],
    channel_states: &'a [RegionPresenceChannels],
    local_member_id: u8,
    local_gone_revision: Option<u64>,
) -> RegionPresenceInput<'a> {
    RegionPresenceInput {
        stream,
        durable_marks,
        channel_states,
        capacity: RegionPresenceCapacity {
            maximum_entries: 16,
        },
        local_member_id,
        local_gone_revision,
    }
}

fn current_stream(origin: RegionPresenceOrigin) -> RegionPresenceStream {
    RegionPresenceStream {
        origin,
        is_current: true,
    }
}

fn entry_for_owner(
    table: &RegionPresenceTable,
    identity_byte: u8,
) -> Result<&RegionPresenceRecord, String> {
    table
        .entries
        .iter()
        .find(|entry| entry.session.presence.identity == [identity_byte; 32])
        .ok_or_else(|| format!("missing owner {identity_byte}"))
}

fn gone_for(presence: RegionPresence, revision: u64) -> RegionGone {
    RegionGone {
        slot: presence.slot,
        network_id: presence.network_id,
        identity: presence.identity,
        generation: presence.generation,
        incarnation: presence.incarnation,
        reason: RegionGoneReason::Superseded,
        boot_epoch: presence.boot_epoch,
        revision,
    }
}

fn snapshot_slot(owner: RegionOwner) -> [u8; 16] {
    derive_slot_id(&owner.network_id, &owner.identity).map_or([0; 16], |slot| slot)
}

fn snapshot_input<'a>(
    origin: RegionPresenceOrigin,
    durable_marks: &'a [RegionMarks],
) -> RegionSnapshotStagingInput<'a> {
    RegionSnapshotStagingInput {
        control: snapshot_test_support::control_with_id(origin, 2),
        durable_marks,
        durable_store: snapshot_test_support::store(16),
        capacity: RegionSnapshotStagingCapacity {
            maximum_origins: 16,
            maximum_entries: 16,
            maximum_mark_owners: 16,
            maximum_mark_staging_bytes: 64 * 1024,
        },
    }
}

fn snapshot_completion_input<'a>(
    origin: RegionPresenceOrigin,
    snapshot_id: u64,
    durable_marks: &'a [RegionMarks],
    channel_states: &'a [RegionPresenceChannels],
) -> RegionSnapshotCompletionInput<'a> {
    RegionSnapshotCompletionInput {
        control: snapshot_test_support::control_with_id(origin, 2),
        snapshot_id,
        durable_cut_receipt: None,
        durable_marks,
        durable_store: snapshot_test_support::store(16),
        channel_states,
        capacity: RegionPresenceCapacity {
            maximum_entries: 16,
        },
    }
}

fn stage_region_snapshot(
    table: &RegionPresenceTable,
    staging: &RegionSnapshotStagingTable,
    snapshot: RegionSnapshot,
    input: RegionSnapshotStagingInput<'_>,
) -> keynet_proto::RegionSnapshotDecision {
    let RegionSnapshotStagingInput {
        control,
        durable_marks,
        durable_store,
        capacity,
    } = input;
    let effective_store = staging
        .stages
        .iter()
        .find(|stage| stage.control == control)
        .filter(|stage| stage.durable_store.lineage == durable_store.lineage)
        .map_or(durable_store, |stage| {
            if stage.durable_store.durable_revision > durable_store.durable_revision {
                stage.durable_store
            } else {
                durable_store
            }
        });
    let retry_snapshot = snapshot.clone();
    let decision = stage_region_snapshot_raw(
        table,
        staging,
        snapshot,
        RegionSnapshotStagingInput {
            control,
            durable_marks,
            durable_store: effective_store,
            capacity,
        },
    );
    if decision.disposition == RegionSnapshotDisposition::AwaitingOwnerValidation {
        let request = match snapshot_test_support::validation_request(&decision) {
            Ok(request) => request,
            Err(_) => return decision,
        };
        let validation = snapshot_test_support::unique_validation(request);
        return validate_region_snapshot_owners(
            &decision.table,
            &decision.staging,
            RegionSnapshotOwnerValidationInput {
                control,
                validation: &validation,
                durable_marks,
                durable_store: effective_store,
                capacity,
            },
        );
    }
    if decision.disposition != RegionSnapshotDisposition::DurableMarkBatchPending {
        return decision;
    }
    let Some(stage) = staging.stages.iter().find(|stage| stage.control == control) else {
        return decision;
    };
    let Some(batch) = stage.pending_mark_batch.as_ref() else {
        return decision;
    };
    let acknowledgment_store = if batch.requires_revision_advance {
        let Some(durable_revision) = effective_store.durable_revision.checked_add(1) else {
            return decision;
        };
        keynet_proto::RegionSnapshotDurableStore {
            lineage: effective_store.lineage,
            durable_revision,
        }
    } else {
        effective_store
    };
    let drained = acknowledge_region_snapshot_durable_batch(
        table,
        staging,
        RegionSnapshotDurableBatchAcknowledgmentInput {
            control,
            acknowledgment: RegionSnapshotDurableBatchAcknowledgment {
                control,
                snapshot_id: stage.snapshot_id,
                base_revision: stage.base_revision,
                marks_revision: stage.marks_revision,
                chunk_index: batch.chunk_index,
                accepted_through: batch.chunk_index,
                commitment: batch.commitment,
                durable_store: acknowledgment_store,
            },
            durable_marks,
            durable_store: acknowledgment_store,
        },
    );
    if matches!(
        drained.disposition,
        RegionSnapshotDisposition::Staged | RegionSnapshotDisposition::AwaitingDurableMarks
    ) {
        return stage_region_snapshot(
            &drained.table,
            &drained.staging,
            retry_snapshot,
            RegionSnapshotStagingInput {
                control,
                durable_marks,
                durable_store: acknowledgment_store,
                capacity,
            },
        );
    }
    decision
}

fn complete_region_snapshot(
    table: &RegionPresenceTable,
    staging: &RegionSnapshotStagingTable,
    input: RegionSnapshotCompletionInput<'_>,
) -> keynet_proto::RegionSnapshotDecision {
    let RegionSnapshotCompletionInput {
        control,
        snapshot_id,
        durable_cut_receipt,
        durable_marks,
        durable_store,
        channel_states,
        capacity,
    } = input;
    let mut next_table = table.clone();
    let mut next_staging = staging.clone();
    let mut completion_store = next_staging
        .stages
        .iter()
        .find(|stage| stage.control == control)
        .filter(|stage| stage.durable_store.lineage == durable_store.lineage)
        .map_or(durable_store, |stage| {
            if stage.durable_store.durable_revision > durable_store.durable_revision {
                stage.durable_store
            } else {
                durable_store
            }
        });
    if let Some(stage) = next_staging
        .stages
        .iter()
        .find(|stage| stage.control == control)
        && let Some(batch) = stage.pending_mark_batch.as_ref()
    {
        if batch.requires_revision_advance {
            let Some(durable_revision) = completion_store.durable_revision.checked_add(1) else {
                return complete_region_snapshot_raw(
                    table,
                    staging,
                    RegionSnapshotCompletionInput {
                        control,
                        snapshot_id,
                        durable_cut_receipt,
                        durable_marks,
                        durable_store,
                        channel_states,
                        capacity,
                    },
                );
            };
            completion_store.durable_revision = durable_revision;
        }
        let drained = acknowledge_region_snapshot_durable_batch(
            &next_table,
            &next_staging,
            RegionSnapshotDurableBatchAcknowledgmentInput {
                control,
                acknowledgment: RegionSnapshotDurableBatchAcknowledgment {
                    control,
                    snapshot_id: stage.snapshot_id,
                    base_revision: stage.base_revision,
                    marks_revision: stage.marks_revision,
                    chunk_index: batch.chunk_index,
                    accepted_through: batch.chunk_index,
                    commitment: batch.commitment,
                    durable_store: completion_store,
                },
                durable_marks,
                durable_store: completion_store,
            },
        );
        if !matches!(
            drained.disposition,
            RegionSnapshotDisposition::Staged | RegionSnapshotDisposition::AwaitingDurableMarks
        ) {
            return complete_region_snapshot_raw(
                table,
                staging,
                RegionSnapshotCompletionInput {
                    control,
                    snapshot_id,
                    durable_cut_receipt,
                    durable_marks,
                    durable_store: completion_store,
                    channel_states,
                    capacity,
                },
            );
        }
        next_table = drained.table;
        next_staging = drained.staging;
    }
    let receipt = durable_cut_receipt.or_else(|| {
        next_staging
            .stages
            .iter()
            .find(|stage| {
                stage.control == control
                    && stage.final_received
                    && stage.pending_mark_batch.is_none()
                    && stage.pending_owner_validation.is_none()
            })
            .and_then(|stage| {
                stage
                    .final_chunk_index
                    .map(|accepted_through| RegionSnapshotDurableCutReceipt {
                        control,
                        snapshot_id: stage.snapshot_id,
                        base_revision: stage.base_revision,
                        marks_revision: stage.marks_revision,
                        accepted_through,
                        cut_commitment: stage.cut_commitment,
                        final_batch_commitment: stage.final_batch_commitment,
                        durable_store: completion_store,
                    })
            })
    });
    complete_region_snapshot_raw(
        &next_table,
        &next_staging,
        RegionSnapshotCompletionInput {
            control,
            snapshot_id,
            durable_cut_receipt: receipt,
            durable_marks,
            durable_store: completion_store,
            channel_states,
            capacity,
        },
    )
}

fn interrupt_region_snapshot(
    table: &RegionPresenceTable,
    staging: &RegionSnapshotStagingTable,
    origin: RegionPresenceOrigin,
) -> keynet_proto::RegionSnapshotDecision {
    interrupt_region_snapshot_raw(
        table,
        staging,
        snapshot_test_support::control_with_id(origin, 2),
    )
}

fn begin_region_snapshot_control(
    table: &RegionPresenceTable,
    staging: &RegionSnapshotStagingTable,
    stream: RegionPresenceStream,
) -> keynet_proto::RegionSnapshotDecision {
    begin_region_snapshot_control_raw(
        table,
        staging,
        keynet_proto::RegionSnapshotControl {
            stream,
            local_boot_epoch: 17,
            control_stream_id: 2,
        },
    )
}

fn snapshot_presence_for(
    origin: RegionPresenceOrigin,
    identity_byte: u8,
    generation: u64,
    incarnation: u64,
    revision: u64,
) -> RegionPresence {
    let mut presence = presence_for(origin, identity_byte, 0, generation, incarnation, revision);
    presence.slot = snapshot_slot(RegionOwner {
        network_id: presence.network_id,
        identity: presence.identity,
    });
    presence
}

fn snapshot(
    snapshot_id: u64,
    base_revision: u64,
    marks_revision: u64,
    chunk_index: u32,
    presence_entries: Vec<RegionPresence>,
    mark_entries: Vec<RegionMarks>,
    more: bool,
) -> RegionSnapshot {
    RegionSnapshot {
        snapshot_id,
        base_revision,
        marks_revision,
        chunk_index,
        presence_entries,
        mark_entries,
        more,
    }
}

fn partial_snapshot(
    origin: RegionPresenceOrigin,
    durable_marks: &[RegionMarks],
) -> keynet_proto::RegionSnapshotDecision {
    stage_region_snapshot(
        &RegionPresenceTable::default(),
        &RegionSnapshotStagingTable::default(),
        snapshot(
            9,
            3,
            8,
            0,
            vec![snapshot_presence_for(origin, 0x22, 5, 1, 1)],
            Vec::new(),
            true,
        ),
        snapshot_input(origin, durable_marks),
    )
}

fn partial_stage_was_discarded(
    decision: &keynet_proto::RegionSnapshotDecision,
    origin: RegionPresenceOrigin,
) -> bool {
    !decision
        .staging
        .stages
        .iter()
        .any(|stage| stage.origin == origin)
        && decision
            .table
            .origins
            .iter()
            .any(|state| state.origin == origin && state.snapshot_required)
        && decision
            .table
            .entries
            .iter()
            .filter(|entry| entry.session.origin == origin)
            .all(|entry| !entry.eligible)
}

#[test]
fn empty_snapshot_completes_only_after_durable_finalization() -> Result<(), String> {
    fixture_expect("snapshot_empty", "completion-required")?;
    fixture_expect(
        "snapshot_cut_receipt",
        "local-stream-cut-progress-commitment",
    )?;
    let authenticated = origin(2, 10);
    let staged = stage_region_snapshot(
        &RegionPresenceTable::default(),
        &RegionSnapshotStagingTable::default(),
        RegionSnapshot {
            snapshot_id: 1,
            base_revision: 0,
            marks_revision: 0,
            chunk_index: 0,
            presence_entries: Vec::new(),
            mark_entries: Vec::new(),
            more: false,
        },
        snapshot_input(authenticated, &[]),
    );
    if staged.disposition != RegionSnapshotDisposition::AwaitingDurableMarks
        || !staged.table.entries.is_empty()
        || !staged.effects.is_empty()
    {
        return Err("empty final chunk published before durable completion".to_owned());
    }

    let channel_states = channels(&[authenticated]);
    let completed = complete_region_snapshot(
        &staged.table,
        &staged.staging,
        snapshot_completion_input(authenticated, 1, &[], &channel_states),
    );
    if completed.disposition != RegionSnapshotDisposition::Completed
        || !completed.table.entries.is_empty()
        || completed.table.origins != vec![state(authenticated, 0)]
    {
        return Err("empty final snapshot did not complete exactly once".to_owned());
    }
    Ok(())
}

#[test]
fn snapshot_stages_contiguous_chunks_before_replacing_one_origin() -> Result<(), String> {
    fixture_expect("snapshot_contiguous_indices", "zero-based-contiguous")?;
    fixture_expect("snapshot_unchanged_cuts", "stable")?;
    fixture_expect("snapshot_final_chunk", "more-false-only")?;
    fixture_expect("snapshot_deferred_routes", "no-route-before-completion")?;
    fixture_expect("snapshot_completion", "replace-origin-after-marks")?;
    let incoming = origin(2, 10);
    let unrelated = origin(3, 20);
    let old = snapshot_presence_for(incoming, 0x22, 5, 1, 3);
    let unrelated_presence = snapshot_presence_for(unrelated, 0x23, 5, 1, 2);
    let published = table(
        vec![
            record(incoming, old, false),
            record(unrelated, unrelated_presence, false),
        ],
        vec![state(incoming, 3), state(unrelated, 2)],
    );
    let initial_marks = [marks(0x22, 5, 0), marks(0x23, 5, 0)];
    let replacement = snapshot_presence_for(incoming, 0x22, 6, 1, 4);
    let first = stage_region_snapshot(
        &published,
        &RegionSnapshotStagingTable::default(),
        snapshot(7, 4, 9, 0, vec![replacement], Vec::new(), true),
        snapshot_input(incoming, &initial_marks),
    );
    if first.disposition != RegionSnapshotDisposition::Staged
        || entry_for_owner(&first.table, 0x22)?.eligible
        || !first.effects.is_empty()
    {
        return Err("a non-final snapshot chunk authorized a route or effect".to_owned());
    }
    let channel_states = channels(&[incoming, unrelated]);
    let incomplete = complete_region_snapshot(
        &first.table,
        &first.staging,
        snapshot_completion_input(incoming, 7, &initial_marks, &channel_states),
    );
    if incomplete.disposition != RegionSnapshotDisposition::IncompleteSnapshot
        || incomplete.table != first.table
    {
        return Err("a snapshot completed before its final chunk".to_owned());
    }

    let joined_mark = marks(0x22, 6, 0);
    let final_chunk = stage_region_snapshot(
        &first.table,
        &first.staging,
        snapshot(7, 4, 9, 1, Vec::new(), vec![joined_mark], false),
        snapshot_input(incoming, &initial_marks),
    );
    if final_chunk.disposition != RegionSnapshotDisposition::AwaitingDurableMarks
        || !snapshot_test_support::is_durable_batch_for(&final_chunk, joined_mark)
        || entry_for_owner(&final_chunk.table, 0x22)?.eligible
    {
        return Err("the final chunk did not defer publication behind durable marks".to_owned());
    }

    let persisted_marks = [joined_mark, marks(0x23, 5, 0)];
    let completed = complete_region_snapshot(
        &final_chunk.table,
        &final_chunk.staging,
        snapshot_completion_input(incoming, 7, &persisted_marks, &channel_states),
    );
    if completed.disposition != RegionSnapshotDisposition::Completed
        || entry_for_owner(&completed.table, 0x22)?.session.presence != replacement
        || entry_for_owner(&completed.table, 0x23)?.session
            != (RegionPresenceSession {
                origin: unrelated,
                presence: unrelated_presence,
            })
    {
        return Err("completion did not replace exactly the incoming origin presence".to_owned());
    }
    Ok(())
}

#[test]
fn nonfinal_mark_joins_stream_before_invalidation_and_backpressure() -> Result<(), String> {
    fixture_expect("snapshot_chunk_mark_persistence", "persist-before-final")?;
    fixture_expect(
        "snapshot_mark_batch_backpressure",
        "drain-before-next-batch",
    )?;
    fixture_expect("snapshot_persisted_marks_survive_invalidation", "preserved")?;
    fixture_expect("snapshot_owner_index_scope", "exact-bounded-store-index")?;
    fixture_expect(
        "snapshot_batch_acknowledgment",
        "local-stream-cut-commitment-revision",
    )?;
    fixture_expect(
        "snapshot_unchanged_batch",
        "identical-floor-no-revision-advance",
    )?;
    fixture_expect("snapshot_replay_fence_capacity", "consume-before-admission")?;
    let authenticated = origin(2, 10);
    let initial_marks = [marks(0x22, 5, 0)];
    let joined_mark = marks(0x22, 6, 0);
    let first = stage_region_snapshot(
        &RegionPresenceTable::default(),
        &RegionSnapshotStagingTable::default(),
        snapshot(
            15,
            1,
            8,
            0,
            vec![snapshot_presence_for(authenticated, 0x22, 6, 1, 1)],
            vec![joined_mark],
            true,
        ),
        snapshot_input(authenticated, &initial_marks),
    );
    if first.disposition != RegionSnapshotDisposition::Staged
        || !snapshot_test_support::is_durable_batch_for(&first, joined_mark)
        || !first.table.entries.is_empty()
    {
        return Err(
            "a non-final mark chunk did not request durable persistence while routes remained closed"
                .to_owned(),
        );
    }

    let blocked = stage_region_snapshot(
        &first.table,
        &first.staging,
        snapshot(15, 1, 8, 1, Vec::new(), vec![marks(0x23, 5, 0)], false),
        snapshot_input(authenticated, &initial_marks),
    );
    if blocked.table != first.table
        || blocked.staging != first.staging
        || !blocked.effects.is_empty()
        || blocked.disposition != RegionSnapshotDisposition::DurableMarkBatchPending
    {
        return Err("a second mark batch was accepted before the prior batch drained".to_owned());
    }

    let durable_after_first = [joined_mark];
    let next_mark = marks(0x23, 5, 0);
    let drained = stage_region_snapshot(
        &first.table,
        &first.staging,
        snapshot(15, 1, 8, 1, Vec::new(), vec![next_mark], false),
        snapshot_input(authenticated, &durable_after_first),
    );
    if drained.disposition != RegionSnapshotDisposition::AwaitingDurableMarks
        || !snapshot_test_support::is_durable_batch_for(&drained, next_mark)
        || !drained.table.entries.is_empty()
    {
        return Err(
            "a drained mark batch did not remain route-closed before completion".to_owned(),
        );
    }

    let durable_before_failure = durable_after_first;
    let malformed = stage_region_snapshot(
        &first.table,
        &first.staging,
        snapshot(15, 2, 8, 1, Vec::new(), Vec::new(), false),
        snapshot_input(authenticated, &durable_after_first),
    );
    let interrupted = interrupt_region_snapshot(&first.table, &first.staging, authenticated);
    if malformed.disposition != RegionSnapshotDisposition::ChangedSnapshotCuts
        || !partial_stage_was_discarded(&malformed, authenticated)
        || interrupted.disposition != RegionSnapshotDisposition::Interrupted
        || !partial_stage_was_discarded(&interrupted, authenticated)
        || durable_after_first != durable_before_failure
    {
        return Err(
            "snapshot invalidation did not discard staged presence while preserving persisted marks"
                .to_owned(),
        );
    }
    Ok(())
}

#[test]
fn changed_or_noncontiguous_chunks_discard_partial_presence() -> Result<(), String> {
    fixture_expect("snapshot_changed_cuts", "discard-partial")?;
    fixture_expect("snapshot_changed_id", "discard-partial")?;
    fixture_expect("snapshot_duplicate_index", "discard-partial")?;
    fixture_expect("snapshot_gap", "discard-partial")?;
    fixture_expect("snapshot_exhaustion", "discard-partial")?;
    let authenticated = origin(2, 10);
    let durable_marks = [marks(0x22, 5, 0)];
    let before = durable_marks;

    let partial = partial_snapshot(authenticated, &durable_marks);
    let changed = stage_region_snapshot(
        &partial.table,
        &partial.staging,
        snapshot(9, 4, 8, 1, Vec::new(), Vec::new(), false),
        snapshot_input(authenticated, &durable_marks),
    );
    if changed.disposition != RegionSnapshotDisposition::ChangedSnapshotCuts
        || !partial_stage_was_discarded(&changed, authenticated)
        || durable_marks != before
    {
        return Err("changed snapshot cuts retained partial state or changed marks".to_owned());
    }

    let partial = partial_snapshot(authenticated, &durable_marks);
    let changed_id = stage_region_snapshot(
        &partial.table,
        &partial.staging,
        snapshot(10, 3, 8, 1, Vec::new(), Vec::new(), false),
        snapshot_input(authenticated, &durable_marks),
    );
    if changed_id.disposition != RegionSnapshotDisposition::UnexpectedSnapshotId
        || !partial_stage_was_discarded(&changed_id, authenticated)
        || durable_marks != before
    {
        return Err(
            "a changed snapshot identifier retained partial state or changed marks".to_owned(),
        );
    }

    let partial = partial_snapshot(authenticated, &durable_marks);
    let duplicate = stage_region_snapshot(
        &partial.table,
        &partial.staging,
        snapshot(9, 3, 8, 0, Vec::new(), Vec::new(), false),
        snapshot_input(authenticated, &durable_marks),
    );
    if duplicate.disposition != RegionSnapshotDisposition::DuplicateChunkIndex
        || !partial_stage_was_discarded(&duplicate, authenticated)
        || durable_marks != before
    {
        return Err("duplicate chunk index retained partial state or changed marks".to_owned());
    }

    let partial = partial_snapshot(authenticated, &durable_marks);
    let gap = stage_region_snapshot(
        &partial.table,
        &partial.staging,
        snapshot(9, 3, 8, 2, Vec::new(), Vec::new(), false),
        snapshot_input(authenticated, &durable_marks),
    );
    if gap.disposition != RegionSnapshotDisposition::SkippedChunkIndex
        || !partial_stage_was_discarded(&gap, authenticated)
        || durable_marks != before
    {
        return Err("a skipped chunk index retained partial state or changed marks".to_owned());
    }

    let exhausted_staging = RegionSnapshotStagingTable {
        stages: vec![RegionSnapshotStage {
            origin: authenticated,
            control: snapshot_test_support::control_with_id(authenticated, 2),
            snapshot_id: 12,
            base_revision: 3,
            marks_revision: 8,
            next_chunk_index: u32::MAX,
            accepted_through: Some(u32::MAX - 1),
            presence_entries: Vec::new(),
            indexed_owner_count: 0,
            indexed_owner_bytes: 0,
            pending_mark_batch: None,
            pending_owner_validation: None,
            cut_commitment: RegionSnapshotCutCommitment { digest: [0; 32] },
            final_batch_commitment: None,
            final_chunk_index: None,
            durable_store: snapshot_test_support::store(durable_marks.len() as u64),
            final_received: false,
        }],
        cursors: Vec::new(),
    };
    let exhausted = stage_region_snapshot(
        &RegionPresenceTable::default(),
        &exhausted_staging,
        snapshot(12, 3, 8, u32::MAX, Vec::new(), Vec::new(), true),
        snapshot_input(authenticated, &durable_marks),
    );
    if exhausted.disposition != RegionSnapshotDisposition::ChunkIndexExhausted
        || !partial_stage_was_discarded(&exhausted, authenticated)
        || durable_marks != before
    {
        return Err("chunk-index exhaustion retained partial state or changed marks".to_owned());
    }
    Ok(())
}

#[test]
fn malformed_snapshot_records_invalidate_without_touching_marks() -> Result<(), String> {
    fixture_expect("snapshot_duplicate_presence_owner", "discard-partial")?;
    fixture_expect("snapshot_duplicate_mark_owner", "discard-partial")?;
    fixture_expect("snapshot_wrong_epoch", "discard-partial")?;
    fixture_expect("snapshot_wrong_slot", "discard-partial")?;
    fixture_expect("snapshot_invalid_revision", "discard-partial")?;
    fixture_expect("snapshot_cut_regression", "discard-partial")?;
    let authenticated = origin(2, 10);
    let durable_marks = [marks(0x22, 5, 0)];
    let before = durable_marks;
    let duplicate_presence = snapshot_presence_for(authenticated, 0x22, 5, 1, 2);
    let partial = partial_snapshot(authenticated, &durable_marks);
    let duplicate = stage_region_snapshot(
        &partial.table,
        &partial.staging,
        snapshot(9, 3, 8, 1, vec![duplicate_presence], Vec::new(), false),
        snapshot_input(authenticated, &durable_marks),
    );
    if duplicate.disposition != RegionSnapshotDisposition::DuplicatePresenceOwner
        || !partial_stage_was_discarded(&duplicate, authenticated)
    {
        return Err("a duplicate presence owner was accepted".to_owned());
    }

    let duplicated_mark = marks(0x22, 5, 0);
    let marked_first_chunk = stage_region_snapshot(
        &RegionPresenceTable::default(),
        &RegionSnapshotStagingTable::default(),
        snapshot(1, 1, 1, 0, Vec::new(), vec![duplicated_mark], true),
        snapshot_input(authenticated, &[]),
    );
    let control = snapshot_test_support::control_with_id(authenticated, 2);
    let stage = marked_first_chunk
        .staging
        .stages
        .iter()
        .find(|stage| stage.control == control)
        .ok_or_else(|| "accepted mark batch lost its staging record".to_owned())?;
    let batch = stage
        .pending_mark_batch
        .as_ref()
        .ok_or_else(|| "accepted mark batch lacked durable evidence".to_owned())?;
    let drained = acknowledge_region_snapshot_durable_batch(
        &marked_first_chunk.table,
        &marked_first_chunk.staging,
        RegionSnapshotDurableBatchAcknowledgmentInput {
            control,
            acknowledgment: RegionSnapshotDurableBatchAcknowledgment {
                control,
                snapshot_id: stage.snapshot_id,
                base_revision: stage.base_revision,
                marks_revision: stage.marks_revision,
                chunk_index: batch.chunk_index,
                accepted_through: batch.chunk_index,
                commitment: batch.commitment,
                durable_store: snapshot_test_support::store(17),
            },
            durable_marks: &[duplicated_mark],
            durable_store: snapshot_test_support::store(17),
        },
    );
    let persisted_mark = [duplicated_mark];
    let mut duplicate_input = snapshot_input(authenticated, &persisted_mark);
    duplicate_input.durable_store = snapshot_test_support::store(17);
    let duplicate_requested = stage_region_snapshot_raw(
        &drained.table,
        &drained.staging,
        snapshot(1, 1, 1, 1, Vec::new(), vec![duplicated_mark], false),
        duplicate_input,
    );
    let duplicate_request = snapshot_test_support::validation_request(&duplicate_requested)?;
    let duplicate_validation = RegionSnapshotOwnerValidation {
        request: duplicate_request,
        outcome: RegionSnapshotOwnerIndexOutcome::Duplicate,
    };
    let duplicate_marks = validate_region_snapshot_owners(
        &duplicate_requested.table,
        &duplicate_requested.staging,
        RegionSnapshotOwnerValidationInput {
            control,
            validation: &duplicate_validation,
            durable_marks: &persisted_mark,
            durable_store: snapshot_test_support::store(17),
            capacity: snapshot_input(authenticated, &persisted_mark).capacity,
        },
    );
    if duplicate_marks.disposition != RegionSnapshotDisposition::DuplicateMarkOwner
        || !partial_stage_was_discarded(&duplicate_marks, authenticated)
    {
        return Err("a duplicate mark owner was accepted".to_owned());
    }

    let mut wrong_epoch = snapshot_presence_for(authenticated, 0x22, 5, 1, 1);
    wrong_epoch.boot_epoch = 11;
    let epoch = stage_region_snapshot(
        &RegionPresenceTable::default(),
        &RegionSnapshotStagingTable::default(),
        snapshot(1, 1, 1, 0, vec![wrong_epoch], Vec::new(), false),
        snapshot_input(authenticated, &durable_marks),
    );
    if epoch.disposition != RegionSnapshotDisposition::InvalidPresenceEpoch
        || !partial_stage_was_discarded(&epoch, authenticated)
    {
        return Err("a mismatched presence epoch was accepted".to_owned());
    }

    let mut wrong_slot = snapshot_presence_for(authenticated, 0x22, 5, 1, 1);
    wrong_slot.slot = [0xff; 16];
    let slot = stage_region_snapshot(
        &RegionPresenceTable::default(),
        &RegionSnapshotStagingTable::default(),
        snapshot(1, 1, 1, 0, vec![wrong_slot], Vec::new(), false),
        snapshot_input(authenticated, &durable_marks),
    );
    if slot.disposition != RegionSnapshotDisposition::InvalidPresenceSlot
        || !partial_stage_was_discarded(&slot, authenticated)
    {
        return Err("a non-derived presence slot was accepted".to_owned());
    }

    let invalid_revision = snapshot_presence_for(authenticated, 0x22, 5, 1, 2);
    let revision = stage_region_snapshot(
        &RegionPresenceTable::default(),
        &RegionSnapshotStagingTable::default(),
        snapshot(1, 1, 1, 0, vec![invalid_revision], Vec::new(), false),
        snapshot_input(authenticated, &durable_marks),
    );
    if revision.disposition != RegionSnapshotDisposition::InvalidPresenceRevision
        || !partial_stage_was_discarded(&revision, authenticated)
    {
        return Err("a revision above the snapshot cut was accepted".to_owned());
    }

    let zero_revision = snapshot_presence_for(authenticated, 0x22, 5, 1, 0);
    let zero = stage_region_snapshot(
        &RegionPresenceTable::default(),
        &RegionSnapshotStagingTable::default(),
        snapshot(1, 1, 1, 0, vec![zero_revision], Vec::new(), false),
        snapshot_input(authenticated, &durable_marks),
    );
    if zero.disposition != RegionSnapshotDisposition::InvalidPresenceRevision
        || !partial_stage_was_discarded(&zero, authenticated)
    {
        return Err("a zero presence revision was accepted".to_owned());
    }

    let regression_table = table(Vec::new(), vec![state(authenticated, 4)]);
    let regression = stage_region_snapshot(
        &regression_table,
        &RegionSnapshotStagingTable::default(),
        snapshot(1, 3, 1, 0, Vec::new(), Vec::new(), false),
        snapshot_input(authenticated, &durable_marks),
    );
    if regression.disposition != RegionSnapshotDisposition::CutRegression
        || !partial_stage_was_discarded(&regression, authenticated)
        || durable_marks != before
    {
        return Err("a cut regression retained partial state or changed marks".to_owned());
    }
    Ok(())
}

#[test]
fn interruption_reconnect_and_completed_ids_require_a_fresh_snapshot() -> Result<(), String> {
    fixture_expect("snapshot_interruption", "discard-partial")?;
    fixture_expect("snapshot_reconnect_restart", "fresh-id-from-zero")?;
    fixture_expect("snapshot_post_completion", "discard-partial")?;
    fixture_expect("snapshot_stale_id", "discard-partial")?;
    let authenticated = origin(2, 10);
    let durable_marks = [marks(0x22, 5, 0)];
    let partial = partial_snapshot(authenticated, &durable_marks);
    let interrupted = interrupt_region_snapshot(&partial.table, &partial.staging, authenticated);
    if interrupted.disposition != RegionSnapshotDisposition::Interrupted
        || !partial_stage_was_discarded(&interrupted, authenticated)
    {
        return Err("an interruption retained partial staged presence".to_owned());
    }
    let restarted = begin_region_snapshot_control(
        &interrupted.table,
        &interrupted.staging,
        current_stream(authenticated),
    );
    let fresh = stage_region_snapshot(
        &restarted.table,
        &restarted.staging,
        snapshot(10, 0, 0, 0, Vec::new(), Vec::new(), false),
        snapshot_input(authenticated, &durable_marks),
    );
    if restarted.disposition != RegionSnapshotDisposition::ControlStarted
        || fresh.disposition != RegionSnapshotDisposition::AwaitingDurableMarks
    {
        return Err("a reconnect did not begin a fresh zero-index snapshot".to_owned());
    }
    let channels = channels(&[authenticated]);
    let completed = complete_region_snapshot(
        &fresh.table,
        &fresh.staging,
        snapshot_completion_input(authenticated, 10, &[], &channels),
    );
    let repeated = stage_region_snapshot(
        &completed.table,
        &completed.staging,
        snapshot(10, 0, 0, 0, Vec::new(), Vec::new(), false),
        snapshot_input(authenticated, &durable_marks),
    );
    let stale = stage_region_snapshot(
        &completed.table,
        &completed.staging,
        snapshot(9, 0, 0, 0, Vec::new(), Vec::new(), false),
        snapshot_input(authenticated, &durable_marks),
    );
    if completed.disposition != RegionSnapshotDisposition::Completed
        || repeated.disposition != RegionSnapshotDisposition::ChunkAfterCompletion
        || stale.disposition != RegionSnapshotDisposition::StaleSnapshotId
        || !partial_stage_was_discarded(&repeated, authenticated)
        || !partial_stage_was_discarded(&stale, authenticated)
    {
        return Err("completed or stale identifiers were accepted".to_owned());
    }
    Ok(())
}

#[test]
fn snapshot_capacity_and_floor_failures_are_explicit_and_route_closed() -> Result<(), String> {
    fixture_expect("snapshot_size_bound", "capacity-exhausted")?;
    fixture_expect("snapshot_mark_compatibility", "discard-partial")?;
    let authenticated = origin(2, 10);
    let durable_marks = [marks(0x22, 5, 0)];
    let mut bounded = snapshot_input(authenticated, &durable_marks);
    bounded.capacity.maximum_entries = 1;
    let overflow = stage_region_snapshot(
        &RegionPresenceTable::default(),
        &RegionSnapshotStagingTable::default(),
        snapshot(
            1,
            1,
            1,
            0,
            vec![
                snapshot_presence_for(authenticated, 0x22, 5, 1, 1),
                snapshot_presence_for(authenticated, 0x23, 5, 1, 1),
            ],
            Vec::new(),
            false,
        ),
        bounded,
    );
    if overflow.disposition != RegionSnapshotDisposition::CapacityExhausted
        || !partial_stage_was_discarded(&overflow, authenticated)
    {
        return Err("snapshot staging capacity overflow was not explicit".to_owned());
    }

    let incompatible_presence = snapshot_presence_for(authenticated, 0x22, 4, 1, 1);
    let joined_mark = marks(0x22, 5, 0);
    let staged = stage_region_snapshot(
        &RegionPresenceTable::default(),
        &RegionSnapshotStagingTable::default(),
        snapshot(
            2,
            1,
            1,
            0,
            vec![incompatible_presence],
            vec![joined_mark],
            false,
        ),
        snapshot_input(authenticated, &[]),
    );
    let channels = channels(&[authenticated]);
    let missing_marks = complete_region_snapshot(
        &staged.table,
        &staged.staging,
        snapshot_completion_input(authenticated, 2, &[], &channels),
    );
    let floor_rejected = complete_region_snapshot(
        &staged.table,
        &staged.staging,
        snapshot_completion_input(authenticated, 2, &[joined_mark], &channels),
    );
    if staged.disposition != RegionSnapshotDisposition::AwaitingDurableMarks
        || missing_marks.disposition != RegionSnapshotDisposition::DurableMarksNotPersisted
        || floor_rejected.disposition != RegionSnapshotDisposition::IncompatiblePresence
        || !partial_stage_was_discarded(&missing_marks, authenticated)
        || !partial_stage_was_discarded(&floor_rejected, authenticated)
    {
        return Err("mark persistence or floor validation authorized a staged route".to_owned());
    }
    Ok(())
}

#[test]
fn generation_precedes_incarnation_in_presence_selection() -> Result<(), String> {
    fixture_expect("generation_before_incarnation", "higher-generation")?;
    let first = origin(2, 10);
    let second = origin(3, 20);
    let existing = presence_for(first, 0x22, 0x31, 4, 99, 1);
    let candidate = presence_for(second, 0x22, 0x32, 5, 1, 1);
    let table = table(
        vec![record(first, existing, false)],
        vec![state(first, 1), state(second, 0)],
    );
    let durable_marks = [marks(0x22, 5, 0)];
    let channel_states = channels(&[first, second]);

    let decision = decide_region_presence(
        &table,
        RegionPresenceEvent::Present(candidate),
        input(
            current_stream(second),
            &durable_marks,
            &channel_states,
            16,
            None,
        ),
    );

    let selected = entry_for_owner(&decision.table, 0x22)?;
    if selected.session.origin != second
        || selected.session.presence.generation != 5
        || selected.session.presence.incarnation != 1
        || !selected.eligible
    {
        return Err("higher generation did not win before incarnation".to_owned());
    }
    Ok(())
}

#[test]
fn higher_generation_stays_selected_when_its_required_channel_is_down() -> Result<(), String> {
    fixture_expect("higher_generation_channel_down", "selected-ineligible")?;
    let local = origin(2, 10);
    let remote = origin(3, 20);
    let existing = presence_for(local, 0x22, 0x31, 4, 99, 1);
    let candidate = presence_for(remote, 0x22, 0x32, 5, 1, 1);
    let table = table(
        vec![record(local, existing, false)],
        vec![state(local, 1), state(remote, 0)],
    );
    let durable_marks = [marks(0x22, 5, 0)];
    let channel_states = [
        RegionPresenceChannels {
            origin: local,
            control_up: true,
            data_up: true,
        },
        RegionPresenceChannels {
            origin: remote,
            control_up: true,
            data_up: false,
        },
    ];

    let decision = decide_region_presence(
        &table,
        RegionPresenceEvent::Present(candidate),
        input(
            current_stream(remote),
            &durable_marks,
            &channel_states,
            2,
            Some(2),
        ),
    );
    let expected_effects = vec![
        RegionPresenceEffect::StopAuthenticatedAcknowledgments(RegionPresenceSession {
            origin: local,
            presence: existing,
        }),
        RegionPresenceEffect::StopForwarding(RegionPresenceSession {
            origin: local,
            presence: existing,
        }),
        RegionPresenceEffect::DropQueuedOutput(RegionPresenceSession {
            origin: local,
            presence: existing,
        }),
        RegionPresenceEffect::EmitMeshGone(gone_for(existing, 2)),
    ];
    let selected = entry_for_owner(&decision.table, 0x22)?;
    if selected.session.origin != remote
        || selected.eligible
        || decision.effects != expected_effects
    {
        return Err("channel eligibility overrode higher-generation selection".to_owned());
    }
    Ok(())
}

#[test]
fn same_origin_lower_generation_cannot_replace_the_selected_session() -> Result<(), String> {
    fixture_expect("same_origin_lower_generation", "retired-lower-generation")?;
    let local = origin(2, 10);
    let existing = presence_for(local, 0x22, 0x31, 5, 1, 1);
    let candidate = presence_for(local, 0x22, 0x32, 4, 99, 2);
    let table = table(vec![record(local, existing, false)], vec![state(local, 1)]);
    let durable_marks = [marks(0x22, 5, 0)];
    let channel_states = channels(&[local]);

    let decision = decide_region_presence(
        &table,
        RegionPresenceEvent::Present(candidate),
        input(
            current_stream(local),
            &durable_marks,
            &channel_states,
            2,
            Some(3),
        ),
    );
    let expected_effects = vec![
        RegionPresenceEffect::StopAuthenticatedAcknowledgments(RegionPresenceSession {
            origin: local,
            presence: candidate,
        }),
        RegionPresenceEffect::StopForwarding(RegionPresenceSession {
            origin: local,
            presence: candidate,
        }),
        RegionPresenceEffect::DropQueuedOutput(RegionPresenceSession {
            origin: local,
            presence: candidate,
        }),
        RegionPresenceEffect::EmitMeshGone(gone_for(candidate, 3)),
    ];
    let selected = entry_for_owner(&decision.table, 0x22)?;
    if selected.session
        != (RegionPresenceSession {
            origin: local,
            presence: existing,
        })
        || !selected.eligible
        || decision.effects != expected_effects
    {
        return Err("same-origin lower generation replaced the selected session".to_owned());
    }
    Ok(())
}

#[test]
fn incarnation_precedes_member_id_in_presence_selection() -> Result<(), String> {
    fixture_expect("incarnation_before_member_id", "higher-incarnation")?;
    let lower_id = origin(1, 10);
    let higher_id = origin(2, 20);
    let existing = presence_for(lower_id, 0x22, 0x31, 5, 4, 1);
    let candidate = presence_for(higher_id, 0x22, 0x32, 5, 5, 1);
    let table = table(
        vec![record(lower_id, existing, false)],
        vec![state(lower_id, 1), state(higher_id, 0)],
    );
    let durable_marks = [marks(0x22, 5, 0)];
    let channel_states = channels(&[lower_id, higher_id]);

    let decision = decide_region_presence(
        &table,
        RegionPresenceEvent::Present(candidate),
        input(
            current_stream(higher_id),
            &durable_marks,
            &channel_states,
            16,
            None,
        ),
    );

    if entry_for_owner(&decision.table, 0x22)?.session.origin != higher_id {
        return Err("member id decided before incarnation".to_owned());
    }
    Ok(())
}

#[test]
fn durable_marks_filter_a_lower_generation_before_member_id() -> Result<(), String> {
    fixture_expect("durable_mark_filtering", "ineligible")?;
    let existing_origin = origin(2, 10);
    let candidate_origin = origin(1, 20);
    let existing = presence_for(existing_origin, 0x22, 0x31, 5, 1, 1);
    let candidate = presence_for(candidate_origin, 0x22, 0x32, 4, 99, 1);
    let table = table(
        vec![record(existing_origin, existing, false)],
        vec![state(existing_origin, 1), state(candidate_origin, 0)],
    );
    let durable_marks = [marks(0x22, 5, 0)];
    let channel_states = channels(&[existing_origin, candidate_origin]);

    let decision = decide_region_presence(
        &table,
        RegionPresenceEvent::Present(candidate),
        input(
            current_stream(candidate_origin),
            &durable_marks,
            &channel_states,
            16,
            None,
        ),
    );

    let selected = entry_for_owner(&decision.table, 0x22)?;
    if selected.session.origin != existing_origin || !selected.eligible {
        return Err("an incompatible mark displaced eligible presence".to_owned());
    }
    Ok(())
}

#[test]
fn lower_member_id_breaks_only_an_equal_eligible_state() -> Result<(), String> {
    fixture_expect("member_id_tie_break", "lower-member-id")?;
    let higher_id = origin(2, 10);
    let lower_id = origin(1, 20);
    let existing = presence_for(higher_id, 0x22, 0x31, 5, 9, 1);
    let candidate = presence_for(lower_id, 0x22, 0x32, 5, 9, 1);
    let table = table(
        vec![record(higher_id, existing, false)],
        vec![state(higher_id, 1), state(lower_id, 0)],
    );
    let durable_marks = [marks(0x22, 5, 9)];
    let channel_states = channels(&[higher_id, lower_id]);

    let decision = decide_region_presence(
        &table,
        RegionPresenceEvent::Present(candidate),
        input(
            current_stream(lower_id),
            &durable_marks,
            &channel_states,
            16,
            None,
        ),
    );

    if entry_for_owner(&decision.table, 0x22)?.session.origin != lower_id {
        return Err("lower member id did not resolve equal eligible state".to_owned());
    }
    Ok(())
}

#[test]
fn presence_entry_uses_the_authenticated_origin() -> Result<(), String> {
    fixture_expect("origin_ownership", "authenticated-origin")?;
    let authenticated = origin(2, 10);
    let presence = presence_for(authenticated, 0x22, 0x31, 5, 1, 1);
    let table = table(Vec::new(), vec![state(authenticated, 0)]);
    let durable_marks = [marks(0x22, 5, 0)];
    let channel_states = channels(&[authenticated]);

    let decision = decide_region_presence(
        &table,
        RegionPresenceEvent::Present(presence),
        input(
            current_stream(authenticated),
            &durable_marks,
            &channel_states,
            16,
            None,
        ),
    );

    if entry_for_owner(&decision.table, 0x22)?.session.origin != authenticated {
        return Err("presence was not owned by the authenticated origin".to_owned());
    }
    Ok(())
}

#[test]
fn full_owner_collision_keeps_one_selected_presence() -> Result<(), String> {
    fixture_expect("full_owner_collision", "single-winner")?;
    let first = origin(2, 10);
    let second = origin(3, 20);
    let existing = presence_for(first, 0x22, 0x31, 5, 1, 1);
    let candidate = presence_for(second, 0x22, 0x32, 5, 2, 1);
    let table = table(
        vec![record(first, existing, false)],
        vec![state(first, 1), state(second, 0)],
    );
    let durable_marks = [marks(0x22, 5, 0)];
    let channel_states = channels(&[first, second]);

    let decision = decide_region_presence(
        &table,
        RegionPresenceEvent::Present(candidate),
        input(
            current_stream(second),
            &durable_marks,
            &channel_states,
            16,
            None,
        ),
    );

    if decision.table.entries.len() != 1
        || entry_for_owner(&decision.table, 0x22)?.session.origin != second
    {
        return Err("full-owner collision retained more than one selected presence".to_owned());
    }
    Ok(())
}

#[test]
fn gone_removes_only_its_exact_originating_session() -> Result<(), String> {
    fixture_expect("exact_gone_removal", "exact-session")?;
    let first = origin(2, 10);
    let second = origin(3, 20);
    let first_presence = presence_for(first, 0x22, 0x31, 5, 4, 1);
    let second_presence = presence_for(second, 0x23, 0x32, 5, 4, 1);
    let table = table(
        vec![
            record(first, first_presence, false),
            record(second, second_presence, false),
        ],
        vec![state(first, 1), state(second, 1)],
    );
    let durable_marks = [marks(0x22, 5, 0), marks(0x23, 5, 0)];
    let channel_states = channels(&[first, second]);
    let mut nonmatching = gone_for(first_presence, 2);
    nonmatching.incarnation = 5;

    let after_nonmatching = decide_region_presence(
        &table,
        RegionPresenceEvent::Gone(nonmatching),
        input(
            current_stream(first),
            &durable_marks,
            &channel_states,
            16,
            None,
        ),
    );
    if after_nonmatching.table.entries.len() != 2 {
        return Err("nonmatching GONE removed a presence".to_owned());
    }

    let after_exact = decide_region_presence(
        &after_nonmatching.table,
        RegionPresenceEvent::Gone(gone_for(first_presence, 3)),
        input(
            current_stream(first),
            &durable_marks,
            &channel_states,
            16,
            None,
        ),
    );
    if after_exact.table.entries.len() != 1
        || entry_for_owner(&after_exact.table, 0x23)?.session
            != (RegionPresenceSession {
                origin: second,
                presence: second_presence,
            })
    {
        return Err("exact GONE did not preserve unrelated presence".to_owned());
    }
    Ok(())
}

#[test]
fn gone_high_water_prevents_an_older_present_from_resurrecting() -> Result<(), String> {
    fixture_expect("revision_high_water", "no-resurrection")?;
    let authenticated = origin(2, 10);
    let presence = presence_for(authenticated, 0x22, 0x31, 5, 4, 1);
    let table = table(
        vec![record(authenticated, presence, false)],
        vec![state(authenticated, 1)],
    );
    let durable_marks = [marks(0x22, 5, 0)];
    let channel_states = channels(&[authenticated]);

    let retired = decide_region_presence(
        &table,
        RegionPresenceEvent::Gone(gone_for(presence, 2)),
        input(
            current_stream(authenticated),
            &durable_marks,
            &channel_states,
            16,
            None,
        ),
    );
    let stale = decide_region_presence(
        &retired.table,
        RegionPresenceEvent::Present(presence),
        input(
            current_stream(authenticated),
            &durable_marks,
            &channel_states,
            16,
            None,
        ),
    );

    if !stale.table.entries.is_empty()
        || stale.disposition != keynet_proto::RegionPresenceDisposition::IgnoredStaleRevision
        || stale.table.origins[0].revision_high_water != 2
    {
        return Err("older PRESENT resurrected an exact GONE session".to_owned());
    }
    Ok(())
}

#[test]
fn stale_stream_event_is_refused_without_state_change() -> Result<(), String> {
    fixture_expect("stale_stream", "refused")?;
    let authenticated = origin(2, 10);
    let presence = presence_for(authenticated, 0x22, 0x31, 5, 4, 1);
    let table = table(
        vec![record(authenticated, presence, false)],
        vec![state(authenticated, 1)],
    );
    let durable_marks = [marks(0x22, 5, 0)];
    let channel_states = channels(&[authenticated]);
    let stale_stream = RegionPresenceStream {
        origin: authenticated,
        is_current: false,
    };
    let newer = presence_for(authenticated, 0x22, 0x32, 5, 5, 2);

    let decision = decide_region_presence(
        &table,
        RegionPresenceEvent::Present(newer),
        input(stale_stream, &durable_marks, &channel_states, 16, None),
    );

    if decision.table != table
        || !decision.effects.is_empty()
        || decision.disposition != keynet_proto::RegionPresenceDisposition::IgnoredStaleStream
    {
        return Err("stale stream event changed presence state".to_owned());
    }
    Ok(())
}

#[test]
fn boot_epoch_replacement_invalidates_routes_and_requires_snapshot() -> Result<(), String> {
    fixture_expect("epoch_replacement", "snapshot-required")?;
    let old_origin = origin(2, 10);
    let new_origin = origin(2, 11);
    let old_presence = presence_for(old_origin, 0x22, 0x31, 5, 4, 1);
    let new_presence = presence_for(new_origin, 0x22, 0x32, 5, 5, 1);
    let table = table(
        vec![record(old_origin, old_presence, false)],
        vec![state(old_origin, 1)],
    );
    let durable_marks = [marks(0x22, 5, 0)];
    let channel_states = channels(&[new_origin]);

    let decision = decide_region_presence(
        &table,
        RegionPresenceEvent::Present(new_presence),
        input(
            current_stream(new_origin),
            &durable_marks,
            &channel_states,
            16,
            None,
        ),
    );

    if !decision.table.entries.is_empty()
        || decision.table.origins.len() != 1
        || decision.table.origins[0].origin != new_origin
        || !decision.table.origins[0].snapshot_required
        || decision.disposition != keynet_proto::RegionPresenceDisposition::ReplacedEpoch
    {
        return Err("boot epoch replacement left an old route usable".to_owned());
    }
    Ok(())
}

#[test]
fn local_loser_emits_only_mesh_retirement_effects_and_keeps_marks() -> Result<(), String> {
    fixture_expect("local_loser_effects", "mesh-gone-only")?;
    fixture_expect("durable_floors_retained", "preserved")?;
    let local = origin(2, 10);
    let remote = origin(1, 20);
    let local_presence = presence_for(local, 0x22, 0x31, 5, 9, 1);
    let remote_presence = presence_for(remote, 0x22, 0x32, 5, 9, 1);
    let table = table(
        vec![record(local, local_presence, false)],
        vec![state(local, 1), state(remote, 0)],
    );
    let durable_marks = [marks(0x22, 5, 9)];
    let durable_marks_before = durable_marks;
    let channel_states = channels(&[local, remote]);

    let decision = decide_region_presence(
        &table,
        RegionPresenceEvent::Present(remote_presence),
        input(
            current_stream(remote),
            &durable_marks,
            &channel_states,
            2,
            Some(2),
        ),
    );
    let expected = vec![
        RegionPresenceEffect::StopAuthenticatedAcknowledgments(RegionPresenceSession {
            origin: local,
            presence: local_presence,
        }),
        RegionPresenceEffect::StopForwarding(RegionPresenceSession {
            origin: local,
            presence: local_presence,
        }),
        RegionPresenceEffect::DropQueuedOutput(RegionPresenceSession {
            origin: local,
            presence: local_presence,
        }),
        RegionPresenceEffect::EmitMeshGone(gone_for(local_presence, 2)),
    ];

    if decision.effects != expected
        || durable_marks != durable_marks_before
        || entry_for_owner(&decision.table, 0x22)?.session.origin != remote
    {
        return Err(
            "local supersession emitted an unexpected effect or changed durable floors".to_owned(),
        );
    }
    Ok(())
}

#[test]
fn grace_cached_presence_is_ineligible_while_a_required_channel_is_down() -> Result<(), String> {
    fixture_expect("grace_channel_down", "ineligible")?;
    let authenticated = origin(2, 10);
    let cached = presence_for(authenticated, 0x22, 0x31, 5, 4, 1);
    let unrelated = presence_for(authenticated, 0x23, 0x32, 5, 1, 2);
    let table = table(
        vec![record(authenticated, cached, true)],
        vec![state(authenticated, 1)],
    );
    let durable_marks = [marks(0x22, 5, 0), marks(0x23, 5, 0)];
    let channel_states = [RegionPresenceChannels {
        origin: authenticated,
        control_up: true,
        data_up: false,
    }];

    let decision = decide_region_presence(
        &table,
        RegionPresenceEvent::Gone(gone_for(unrelated, 2)),
        input(
            current_stream(authenticated),
            &durable_marks,
            &channel_states,
            16,
            None,
        ),
    );
    let retained = entry_for_owner(&decision.table, 0x22)?;
    if !retained.grace_cached || retained.eligible {
        return Err("grace cached presence stayed eligible without a live channel pair".to_owned());
    }
    Ok(())
}

#[test]
fn capacity_is_an_explicit_bound_on_new_presence() -> Result<(), String> {
    fixture_expect("capacity_bound", "no-growth")?;
    let first = origin(2, 10);
    let second = origin(3, 20);
    let existing = presence_for(first, 0x22, 0x31, 5, 1, 1);
    let candidate = presence_for(second, 0x23, 0x32, 5, 1, 1);
    let table = table(
        vec![record(first, existing, false)],
        vec![state(first, 1), state(second, 0)],
    );
    let durable_marks = [marks(0x22, 5, 0), marks(0x23, 5, 0)];
    let channel_states = channels(&[first, second]);
    let mut event_input = input(
        current_stream(second),
        &durable_marks,
        &channel_states,
        16,
        None,
    );
    event_input.capacity.maximum_entries = 1;

    let decision =
        decide_region_presence(&table, RegionPresenceEvent::Present(candidate), event_input);

    if decision.table.entries.len() != 1
        || entry_for_owner(&decision.table, 0x22)?.session.origin != first
        || decision.table.origins[1].revision_high_water != 1
    {
        return Err("capacity bound allowed an additional presence".to_owned());
    }
    Ok(())
}
