use quick_wire::{
    RegionPresenceOrigin, RegionPresenceTable, RegionSnapshot, RegionSnapshotDisposition,
    RegionSnapshotStagingCapacity, RegionSnapshotStagingInput, RegionSnapshotStagingTable,
    begin_region_snapshot_control, interrupt_region_snapshot, stage_region_snapshot,
};

mod snapshot_test_support;

fn input(control: quick_wire::RegionSnapshotControl) -> RegionSnapshotStagingInput<'static> {
    RegionSnapshotStagingInput {
        control,
        durable_marks: &[],
        durable_store: snapshot_test_support::store(0),
        capacity: RegionSnapshotStagingCapacity {
            maximum_origins: 15,
            maximum_entries: 10_000,
            maximum_mark_owners: 10_000,
            maximum_mark_staging_bytes: 64 * 1024,
        },
    }
}

fn chunk(snapshot_id: u64, more: bool) -> RegionSnapshot {
    RegionSnapshot {
        snapshot_id,
        base_revision: 0,
        marks_revision: 0,
        chunk_index: 0,
        presence_entries: Vec::new(),
        mark_entries: Vec::new(),
        more,
    }
}

#[test]
fn an_abandoned_snapshot_id_cannot_be_reused_after_reconnect() -> Result<(), String> {
    let origin = RegionPresenceOrigin {
        member_id: 2,
        boot_epoch: 9,
    };
    let table = RegionPresenceTable::default();
    let staging = RegionSnapshotStagingTable::default();
    let initial_control = snapshot_test_support::control(origin);

    let partial = stage_region_snapshot(&table, &staging, chunk(7, true), input(initial_control));
    if partial.disposition != RegionSnapshotDisposition::Staged {
        return Err("initial snapshot did not stage".to_owned());
    }
    let interrupted = interrupt_region_snapshot(&partial.table, &partial.staging, initial_control);
    let reconnect_control = snapshot_test_support::control_with_id(origin, 2);
    let restarted =
        begin_region_snapshot_control(&interrupted.table, &interrupted.staging, reconnect_control);
    let reused = stage_region_snapshot(
        &restarted.table,
        &restarted.staging,
        chunk(7, false),
        input(reconnect_control),
    );
    let stale = stage_region_snapshot(
        &restarted.table,
        &restarted.staging,
        chunk(6, false),
        input(reconnect_control),
    );
    let fresh = stage_region_snapshot(
        &restarted.table,
        &restarted.staging,
        chunk(8, false),
        input(reconnect_control),
    );

    if reused.disposition == RegionSnapshotDisposition::AwaitingDurableMarks {
        return Err("an abandoned snapshot id was accepted after reconnect".to_owned());
    }
    if reused
        .table
        .origins
        .iter()
        .any(|state| state.origin == origin && !state.snapshot_required)
    {
        return Err("reused snapshot id restored synchronization".to_owned());
    }
    if stale.disposition != RegionSnapshotDisposition::StaleSnapshotId
        || fresh.disposition != RegionSnapshotDisposition::AwaitingDurableMarks
    {
        return Err(
            "fresh snapshot ids did not advance past the abandoned high-water mark".to_owned(),
        );
    }
    Ok(())
}
