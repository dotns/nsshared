use keynet_proto::{
    RegionOwner, RegionPresenceOrigin, RegionPresenceStream, RegionPresenceTable, RegionSnapshot,
    RegionSnapshotDisposition, RegionSnapshotStagingCapacity, RegionSnapshotStagingInput,
    RegionSnapshotStagingTable, begin_region_snapshot_control, interrupt_region_snapshot,
    stage_region_snapshot,
};

fn slot_for_owner(_: RegionOwner) -> [u8; 16] {
    [0; 16]
}

fn input(origin: RegionPresenceOrigin) -> RegionSnapshotStagingInput<'static> {
    RegionSnapshotStagingInput {
        stream: RegionPresenceStream {
            origin,
            is_current: true,
        },
        durable_marks: &[],
        capacity: RegionSnapshotStagingCapacity {
            maximum_origins: 15,
            maximum_entries: 10_000,
        },
        slot_for_owner,
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

    let partial = stage_region_snapshot(&table, &staging, chunk(7, true), input(origin));
    if partial.disposition != RegionSnapshotDisposition::Staged {
        return Err("initial snapshot did not stage".to_owned());
    }
    let interrupted = interrupt_region_snapshot(&partial.table, &partial.staging, origin);
    let restarted = begin_region_snapshot_control(
        &interrupted.table,
        &interrupted.staging,
        RegionPresenceStream {
            origin,
            is_current: true,
        },
    );
    let reused = stage_region_snapshot(
        &restarted.table,
        &restarted.staging,
        chunk(7, false),
        input(origin),
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
    Ok(())
}
