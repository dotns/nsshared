use keynet_proto::{
    RegionMarks, RegionOwner, RegionPresenceOrigin, RegionPresenceStream, RegionPresenceTable,
    RegionSnapshot, RegionSnapshotDisposition, RegionSnapshotStagingCapacity,
    RegionSnapshotStagingInput, RegionSnapshotStagingTable, stage_region_snapshot,
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
    let mut table = RegionPresenceTable::default();
    let mut staging = RegionSnapshotStagingTable::default();
    let mut durable_marks = Vec::new();

    for chunk_index in 0..5_u32 {
        let start = chunk_index as u16 * 256;
        let count = if chunk_index == 4 { 1 } else { 256 };
        let batch = (start..start + count).map(mark).collect::<Vec<_>>();
        let decision = stage_region_snapshot(
            &table,
            &staging,
            RegionSnapshot {
                snapshot_id: 1,
                base_revision: 0,
                marks_revision: 1_025,
                chunk_index,
                presence_entries: Vec::new(),
                mark_entries: batch.clone(),
                more: chunk_index != 4,
            },
            input(origin, &durable_marks),
        );
        let expected = if chunk_index == 4 {
            RegionSnapshotDisposition::AwaitingDurableMarks
        } else {
            RegionSnapshotDisposition::Staged
        };
        if decision.disposition != expected {
            return Err(format!(
                "snapshot stopped before the byte cap with disposition {:?}",
                decision.disposition
            ));
        }
        durable_marks.extend(batch);
        table = decision.table;
        staging = decision.staging;
    }

    let retained_owners = staging
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
    Ok(())
}
