use keynet_proto::{
    RegionCarrier, RegionPresence, RegionPresenceOrigin, RegionPresenceStream, RegionPresenceTable,
    RegionSnapshot, RegionSnapshotDisposition, RegionSnapshotStagingCapacity,
    RegionSnapshotStagingInput, RegionSnapshotStagingTable, derive_slot_id, stage_region_snapshot,
};

fn input(origin: RegionPresenceOrigin) -> RegionSnapshotStagingInput<'static> {
    RegionSnapshotStagingInput {
        stream: RegionPresenceStream {
            origin,
            is_current: true,
        },
        durable_marks: &[],
        capacity: RegionSnapshotStagingCapacity {
            maximum_origins: 15,
            maximum_entries: 0,
            maximum_mark_owners: 1_000_000,
        },
    }
}

fn snapshot(snapshot_id: u64, presence_entries: Vec<RegionPresence>) -> RegionSnapshot {
    RegionSnapshot {
        snapshot_id,
        base_revision: 1,
        marks_revision: 0,
        chunk_index: 0,
        presence_entries,
        mark_entries: Vec::new(),
        more: false,
    }
}

#[test]
fn an_overflowed_snapshot_id_cannot_restart_the_same_epoch() -> Result<(), String> {
    let origin = RegionPresenceOrigin {
        member_id: 2,
        boot_epoch: 9,
    };
    let network_id = [1; 32];
    let identity = [2; 32];
    let slot = derive_slot_id(&network_id, &identity)
        .map_err(|error| format!("slot derivation failed: {error:?}"))?;
    let presence = RegionPresence {
        slot,
        network_id,
        identity,
        generation: 1,
        incarnation: 1,
        carrier: RegionCarrier::Udp,
        boot_epoch: origin.boot_epoch,
        revision: 1,
    };

    let overflowed = stage_region_snapshot(
        &RegionPresenceTable::default(),
        &RegionSnapshotStagingTable::default(),
        snapshot(7, vec![presence]),
        input(origin),
    );
    if overflowed.disposition != RegionSnapshotDisposition::CapacityExhausted {
        return Err("initial snapshot did not exhaust the configured capacity".to_owned());
    }

    let reused = stage_region_snapshot(
        &overflowed.table,
        &overflowed.staging,
        snapshot(7, Vec::new()),
        input(origin),
    );
    if reused.disposition == RegionSnapshotDisposition::AwaitingDurableMarks {
        return Err("capacity-invalidated snapshot id was accepted again".to_owned());
    }
    Ok(())
}
