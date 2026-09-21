use keynet_proto::{
    RegionMarks, RegionOwner, RegionPresenceOrigin, RegionPresenceStream, RegionPresenceTable,
    RegionSnapshot, RegionSnapshotDisposition, RegionSnapshotStagingCapacity,
    RegionSnapshotStagingInput, RegionSnapshotStagingTable, stage_region_snapshot,
};

fn slot_for_owner(_: RegionOwner) -> [u8; 16] {
    [0; 16]
}

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
        },
        slot_for_owner,
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
    Ok(())
}
