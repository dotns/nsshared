use quick_wire::{
    RegionCarrier, RegionGone, RegionGoneReason, RegionMarks, RegionPresence,
    RegionPresenceCapacity, RegionPresenceChannels, RegionPresenceDisposition, RegionPresenceEvent,
    RegionPresenceInput, RegionPresenceOrigin, RegionPresenceOriginState, RegionPresenceRecord,
    RegionPresenceSession, RegionPresenceStream, RegionPresenceTable, decide_region_presence,
};

#[test]
fn stale_callback_cannot_leave_grace_presence_eligible_after_channel_loss() {
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
    let table = RegionPresenceTable {
        entries: vec![RegionPresenceRecord {
            session: RegionPresenceSession { origin, presence },
            eligible: true,
            grace_cached: true,
        }],
        origins: vec![RegionPresenceOriginState {
            origin,
            revision_high_water: 1,
            snapshot_required: false,
        }],
    };
    let durable_marks = [RegionMarks {
        network_id: presence.network_id,
        identity: presence.identity,
        committed_generation: presence.generation,
        committed_key: [0x44; 32],
        conflicted: false,
        revoked_through: None,
        incarnation_high_water: presence.incarnation,
    }];
    let channel_states = [RegionPresenceChannels {
        origin,
        control_up: true,
        data_up: false,
    }];
    let stale_gone = RegionGone {
        slot: presence.slot,
        network_id: presence.network_id,
        identity: presence.identity,
        generation: presence.generation,
        incarnation: presence.incarnation,
        reason: RegionGoneReason::Expired,
        boot_epoch: origin.boot_epoch,
        revision: 2,
    };

    let decision = decide_region_presence(
        &table,
        RegionPresenceEvent::Gone(stale_gone),
        RegionPresenceInput {
            stream: RegionPresenceStream {
                origin,
                is_current: false,
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
        RegionPresenceDisposition::IgnoredStaleStream
    );
    assert_eq!(decision.table.entries.len(), 1);
    assert!(
        !decision.table.entries[0].eligible,
        "stale callback left grace-cached presence eligible with data down"
    );
}
