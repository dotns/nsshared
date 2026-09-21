use keynet_proto::{
    RegionCarrier, RegionMarks, RegionPresence, RegionPresenceCapacity, RegionPresenceChannels,
    RegionPresenceDisposition, RegionPresenceEvent, RegionPresenceInput, RegionPresenceOrigin,
    RegionPresenceOriginState, RegionPresenceRecord, RegionPresenceSession, RegionPresenceStream,
    RegionPresenceTable, decide_region_presence,
};

fn presence(origin: RegionPresenceOrigin, generation: u64, revision: u64) -> RegionPresence {
    RegionPresence {
        slot: [origin.member_id; 16],
        network_id: [0x11; 32],
        identity: [0x22; 32],
        generation,
        incarnation: 1,
        carrier: RegionCarrier::Udp,
        boot_epoch: origin.boot_epoch,
        revision,
    }
}

#[test]
fn missing_retirement_revision_cannot_restore_mark_incompatible_eligibility() {
    let local = RegionPresenceOrigin {
        member_id: 2,
        boot_epoch: 10,
    };
    let remote = RegionPresenceOrigin {
        member_id: 3,
        boot_epoch: 20,
    };
    let stale_local = presence(local, 4, 1);
    let replacement = presence(remote, 5, 1);
    let table = RegionPresenceTable {
        entries: vec![RegionPresenceRecord {
            session: RegionPresenceSession {
                origin: local,
                presence: stale_local,
            },
            eligible: true,
            grace_cached: false,
        }],
        origins: vec![
            RegionPresenceOriginState {
                origin: local,
                revision_high_water: 1,
                snapshot_required: false,
            },
            RegionPresenceOriginState {
                origin: remote,
                revision_high_water: 0,
                snapshot_required: false,
            },
        ],
    };
    let durable_marks = [RegionMarks {
        network_id: stale_local.network_id,
        identity: stale_local.identity,
        committed_generation: 5,
        committed_key: [0x44; 32],
        conflicted: false,
        revoked_through: None,
        incarnation_high_water: 1,
    }];
    let channel_states = [
        RegionPresenceChannels {
            origin: local,
            control_up: true,
            data_up: true,
        },
        RegionPresenceChannels {
            origin: remote,
            control_up: true,
            data_up: true,
        },
    ];

    let decision = decide_region_presence(
        &table,
        RegionPresenceEvent::Present(replacement),
        RegionPresenceInput {
            stream: RegionPresenceStream {
                origin: remote,
                is_current: true,
            },
            durable_marks: &durable_marks,
            channel_states: &channel_states,
            capacity: RegionPresenceCapacity { maximum_entries: 1 },
            local_member_id: local.member_id,
            local_gone_revision: None,
        },
    );

    assert_eq!(
        decision.disposition,
        RegionPresenceDisposition::MissingLocalRetirementRevision
    );
    assert_eq!(decision.table.entries.len(), 1);
    assert!(
        !decision.table.entries[0].eligible,
        "retirement error restored eligibility below the durable generation"
    );
}
