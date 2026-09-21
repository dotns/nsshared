use keynet_proto::{
    RegionCarrier, RegionOwner, RegionPresence, RegionPresenceOrigin, RegionPresenceStream,
    RegionPresenceTable, RegionSnapshot, RegionSnapshotDisposition, RegionSnapshotStagingCapacity,
    RegionSnapshotStagingInput, RegionSnapshotStagingTable, derive_slot_id, stage_region_snapshot,
};

fn accept_claimed_slot(_: RegionOwner) -> [u8; 16] {
    [0xaa; 16]
}

#[test]
fn snapshot_slot_validation_uses_the_protocol_derivation() -> Result<(), String> {
    let origin = RegionPresenceOrigin {
        member_id: 2,
        boot_epoch: 9,
    };
    let network_id = [1; 32];
    let identity = [2; 32];
    let claimed_slot = [0xaa; 16];
    let canonical_slot = derive_slot_id(&network_id, &identity)
        .map_err(|error| format!("canonical slot derivation failed: {error:?}"))?;
    if canonical_slot == claimed_slot {
        return Err("test input unexpectedly used the canonical slot".to_owned());
    }

    let decision = stage_region_snapshot(
        &RegionPresenceTable::default(),
        &RegionSnapshotStagingTable::default(),
        RegionSnapshot {
            snapshot_id: 1,
            base_revision: 1,
            marks_revision: 0,
            chunk_index: 0,
            presence_entries: vec![RegionPresence {
                slot: claimed_slot,
                network_id,
                identity,
                generation: 1,
                incarnation: 1,
                carrier: RegionCarrier::Udp,
                boot_epoch: origin.boot_epoch,
                revision: 1,
            }],
            mark_entries: Vec::new(),
            more: false,
        },
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
            slot_for_owner: accept_claimed_slot,
        },
    );

    if decision.disposition != RegionSnapshotDisposition::InvalidPresenceSlot {
        return Err(format!(
            "noncanonical slot was accepted with disposition {:?}",
            decision.disposition
        ));
    }
    Ok(())
}
