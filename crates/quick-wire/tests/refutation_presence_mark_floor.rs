use quick_wire::{
    RegionCarrier, RegionMarks, RegionPresence, RegionPresenceCapacity, RegionPresenceChannels,
    RegionPresenceEvent, RegionPresenceInput, RegionPresenceOrigin, RegionPresenceOriginState,
    RegionPresenceStream, RegionPresenceTable, decide_region_presence,
};

#[test]
fn presence_cannot_route_before_its_generation_mark_is_durable() {
    let origin = RegionPresenceOrigin {
        member_id: 2,
        boot_epoch: 10,
    };
    let presence = RegionPresence {
        slot: [0x31; 16],
        network_id: [0x11; 32],
        identity: [0x22; 32],
        generation: 5,
        incarnation: 1,
        carrier: RegionCarrier::Udp,
        boot_epoch: origin.boot_epoch,
        revision: 1,
    };
    let durable_marks = [RegionMarks {
        network_id: presence.network_id,
        identity: presence.identity,
        committed_generation: 4,
        committed_key: [0x44; 32],
        conflicted: false,
        revoked_through: None,
        incarnation_high_water: 0,
    }];
    let channel_states = [RegionPresenceChannels {
        origin,
        control_up: true,
        data_up: true,
    }];
    let table = RegionPresenceTable {
        entries: Vec::new(),
        origins: vec![RegionPresenceOriginState {
            origin,
            revision_high_water: 0,
            snapshot_required: false,
        }],
    };

    let decision = decide_region_presence(
        &table,
        RegionPresenceEvent::Present(presence),
        RegionPresenceInput {
            stream: RegionPresenceStream {
                origin,
                is_current: true,
            },
            durable_marks: &durable_marks,
            channel_states: &channel_states,
            capacity: RegionPresenceCapacity { maximum_entries: 1 },
            local_member_id: 1,
            local_gone_revision: None,
        },
    );

    assert_eq!(decision.table.entries.len(), 1);
    assert!(
        !decision.table.entries[0].eligible,
        "presence became eligible before its generation-specific mark was durable"
    );
}
