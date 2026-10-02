use quick_wire::{
    RegionCarrier, RegionPresence, RegionPresenceOrigin, RegionPresenceTable, RegionSnapshot,
    RegionSnapshotDisposition, RegionSnapshotStagingCapacity, RegionSnapshotStagingInput,
    RegionSnapshotStagingTable, begin_region_snapshot_control, derive_slot_id,
    stage_region_snapshot,
};

mod snapshot_test_support;

fn input(control: quick_wire::RegionSnapshotControl) -> RegionSnapshotStagingInput<'static> {
    RegionSnapshotStagingInput {
        control,
        durable_marks: &[],
        durable_store: snapshot_test_support::store(0),
        capacity: RegionSnapshotStagingCapacity {
            maximum_origins: 15,
            maximum_entries: 0,
            maximum_mark_owners: 1_000_000,
            maximum_mark_staging_bytes: 64 * 1024,
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
    let initial_control = snapshot_test_support::control(origin);

    let overflowed = stage_region_snapshot(
        &RegionPresenceTable::default(),
        &RegionSnapshotStagingTable::default(),
        snapshot(7, vec![presence]),
        input(initial_control),
    );
    if overflowed.disposition != RegionSnapshotDisposition::CapacityExhausted {
        return Err("initial snapshot did not exhaust the configured capacity".to_owned());
    }

    let reconnect_control = snapshot_test_support::control_with_id(origin, 2);
    let restarted =
        begin_region_snapshot_control(&overflowed.table, &overflowed.staging, reconnect_control);
    if restarted.disposition != RegionSnapshotDisposition::ControlStarted {
        return Err("reconnect did not start a fresh control synchronization".to_owned());
    }

    let reused = stage_region_snapshot(
        &restarted.table,
        &restarted.staging,
        snapshot(7, Vec::new()),
        input(reconnect_control),
    );
    if reused.disposition == RegionSnapshotDisposition::AwaitingDurableMarks
        || reused
            .staging
            .stages
            .iter()
            .any(|stage| stage.origin == origin)
    {
        return Err("capacity-invalidated snapshot id was accepted again".to_owned());
    }

    let fresh = stage_region_snapshot(
        &reused.table,
        &reused.staging,
        snapshot(8, Vec::new()),
        input(reconnect_control),
    );
    if fresh.disposition != RegionSnapshotDisposition::AwaitingDurableMarks {
        return Err("a fresh snapshot id was not accepted after overflow".to_owned());
    }
    Ok(())
}
