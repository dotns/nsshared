use keynet_proto::{
    MAX_REGION_SNAPSHOT_MARK_STAGING_BYTES, RegionMarks, RegionOwner, RegionPresenceOrigin,
    RegionPresenceStream, RegionPresenceTable, RegionSnapshot, RegionSnapshotDisposition,
    RegionSnapshotStagingCapacity, RegionSnapshotStagingInput, RegionSnapshotStagingTable,
    stage_region_snapshot,
};

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
    maximum_mark_staging_bytes: usize,
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
    let first_batch = (0..256).map(mark).collect::<Vec<_>>();
    let first = stage_region_snapshot(
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
        input(origin, &[], MAX_REGION_SNAPSHOT_MARK_STAGING_BYTES),
    );
    if first.disposition != RegionSnapshotDisposition::Staged || first.effects.len() != 256 {
        return Err("the initial mark batch did not fit the explicit byte budget".to_owned());
    }

    let retained_owners = first
        .staging
        .stages
        .iter()
        .find(|stage| stage.origin == origin)
        .ok_or_else(|| "accepted snapshot lost its stage".to_owned())?
        .mark_owners
        .len();
    let retained_owner_bytes = retained_owners
        .checked_mul(std::mem::size_of::<RegionOwner>())
        .ok_or_else(|| "owner byte accounting overflowed".to_owned())?;
    if retained_owner_bytes > 64 * 1024 {
        return Err(format!(
            "snapshot retained {retained_owner_bytes} bytes of mark-owner index"
        ));
    }

    let retained_mark_bytes = first
        .staging
        .stages
        .iter()
        .find(|stage| stage.origin == origin)
        .ok_or_else(|| "accepted snapshot lost its stage".to_owned())?
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
        input(origin, &[], lower_mark_budget),
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

    let second_batch = (256..512).map(mark).collect::<Vec<_>>();
    let overflow = stage_region_snapshot(
        &first.table,
        &first.staging,
        RegionSnapshot {
            snapshot_id: 1,
            base_revision: 0,
            marks_revision: 512,
            chunk_index: 1,
            presence_entries: Vec::new(),
            mark_entries: second_batch,
            more: false,
        },
        input(origin, &first_batch, MAX_REGION_SNAPSHOT_MARK_STAGING_BYTES),
    );
    if overflow.disposition != RegionSnapshotDisposition::CapacityExhausted
        || overflow
            .staging
            .stages
            .iter()
            .any(|stage| stage.origin == origin)
        || !overflow.table.entries.is_empty()
    {
        return Err("mark staging did not fail closed at the explicit byte cap".to_owned());
    }
    Ok(())
}
