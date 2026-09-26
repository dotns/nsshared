use keynet_proto::{
    RegionCarrier, RegionMarks, RegionPresence, RegionPresenceCapacity, RegionPresenceChannels,
    RegionPresenceDisposition, RegionPresenceEvent, RegionPresenceInput, RegionPresenceOrigin,
    RegionPresenceOriginState, RegionPresenceRecord, RegionPresenceSession, RegionPresenceStream,
    RegionPresenceTable, decide_region_presence,
};

fn presence(origin: RegionPresenceOrigin, identity: u8, revision: u64) -> RegionPresence {
    RegionPresence {
        slot: [identity; 16],
        network_id: [0x11; 32],
        identity: [identity; 32],
        generation: 5,
        incarnation: 1,
        carrier: RegionCarrier::Udp,
        boot_epoch: origin.boot_epoch,
        revision,
    }
}

fn marks(identity: u8) -> RegionMarks {
    RegionMarks {
        network_id: [0x11; 32],
        identity: [identity; 32],
        committed_generation: 5,
        committed_key: [0x44; 32],
        conflicted: false,
        revoked_through: None,
        incarnation_high_water: 1,
    }
}

#[test]
fn presence_capacity_overflow_invalidates_origin_synchronization() {
    let first_origin = RegionPresenceOrigin {
        member_id: 2,
        boot_epoch: 10,
    };
    let overflowing_origin = RegionPresenceOrigin {
        member_id: 3,
        boot_epoch: 20,
    };
    let first_presence = presence(first_origin, 0x22, 1);
    let overflowing_presence = presence(overflowing_origin, 0x23, 1);
    let table = RegionPresenceTable {
        entries: vec![RegionPresenceRecord {
            session: RegionPresenceSession {
                origin: first_origin,
                presence: first_presence,
            },
            eligible: true,
            grace_cached: false,
        }],
        origins: vec![
            RegionPresenceOriginState {
                origin: first_origin,
                revision_high_water: 1,
                snapshot_required: false,
            },
            RegionPresenceOriginState {
                origin: overflowing_origin,
                revision_high_water: 0,
                snapshot_required: false,
            },
        ],
    };
    let durable_marks = [marks(0x22), marks(0x23)];
    let channel_states = [
        RegionPresenceChannels {
            origin: first_origin,
            control_up: true,
            data_up: true,
        },
        RegionPresenceChannels {
            origin: overflowing_origin,
            control_up: true,
            data_up: true,
        },
    ];

    let decision = decide_region_presence(
        &table,
        RegionPresenceEvent::Present(overflowing_presence),
        RegionPresenceInput {
            stream: RegionPresenceStream {
                origin: overflowing_origin,
                is_current: true,
            },
            durable_marks: &durable_marks,
            channel_states: &channel_states,
            capacity: RegionPresenceCapacity { maximum_entries: 1 },
            local_member_id: 1,
            local_gone_revision: None,
        },
    );

    assert_eq!(
        decision.disposition,
        RegionPresenceDisposition::CapacityExhausted
    );
    let snapshot_required = decision
        .table
        .origins
        .iter()
        .find(|state| state.origin == overflowing_origin)
        .is_some_and(|state| state.snapshot_required);
    assert!(
        snapshot_required,
        "capacity overflow left the origin synchronized after dropping presence"
    );
}
