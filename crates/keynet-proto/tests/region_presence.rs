use keynet_proto::{
    RegionCarrier, RegionGone, RegionGoneReason, RegionMarks, RegionPresence,
    RegionPresenceCapacity, RegionPresenceChannels, RegionPresenceEffect, RegionPresenceEvent,
    RegionPresenceInput, RegionPresenceOrigin, RegionPresenceOriginState, RegionPresenceRecord,
    RegionPresenceSession, RegionPresenceStream, RegionPresenceTable, decide_region_presence,
};
use std::{collections::BTreeMap, fs, path::PathBuf};

const ROOT: &str = "tests/fixtures/keynet-v1";

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(ROOT)
        .join("region_presence.vec")
}

fn fixture_expect(case_name: &str, expected: &str) -> Result<(), String> {
    let text = fs::read_to_string(fixture_path()).map_err(|error| error.to_string())?;
    let mut cases = BTreeMap::new();
    for block in text.split("\n\n").filter(|block| !block.trim().is_empty()) {
        let mut fields = BTreeMap::new();
        for line in block.lines().filter(|line| !line.starts_with('#')) {
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| "invalid region presence vector line".to_owned())?;
            if fields.insert(key, value).is_some() {
                return Err(format!("duplicate region presence vector field: {key}"));
            }
        }
        if fields.len() != 2 {
            return Err("region presence vector must have exactly two fields".to_owned());
        }
        let name = fields
            .get("case")
            .ok_or_else(|| "region presence vector lacks case".to_owned())?;
        let value = fields
            .get("expected")
            .ok_or_else(|| "region presence vector lacks expected".to_owned())?;
        if cases
            .insert((*name).to_owned(), (*value).to_owned())
            .is_some()
        {
            return Err(format!("duplicate region presence vector case: {name}"));
        }
    }
    if cases.get(case_name).is_none_or(|actual| actual != expected) {
        return Err(format!("unexpected sealed expectation for {case_name}"));
    }
    Ok(())
}

fn origin(member_id: u8, boot_epoch: u64) -> RegionPresenceOrigin {
    RegionPresenceOrigin {
        member_id,
        boot_epoch,
    }
}

fn presence_for(
    origin: RegionPresenceOrigin,
    identity_byte: u8,
    slot_byte: u8,
    generation: u64,
    incarnation: u64,
    revision: u64,
) -> RegionPresence {
    RegionPresence {
        slot: [slot_byte; 16],
        network_id: [0x11; 32],
        identity: [identity_byte; 32],
        generation,
        incarnation,
        carrier: RegionCarrier::Udp,
        boot_epoch: origin.boot_epoch,
        revision,
    }
}

fn record(
    origin: RegionPresenceOrigin,
    presence: RegionPresence,
    grace_cached: bool,
) -> RegionPresenceRecord {
    RegionPresenceRecord {
        session: RegionPresenceSession { origin, presence },
        eligible: true,
        grace_cached,
    }
}

fn marks(identity_byte: u8, generation: u64, incarnation_high_water: u64) -> RegionMarks {
    RegionMarks {
        network_id: [0x11; 32],
        identity: [identity_byte; 32],
        committed_generation: generation,
        committed_key: [0x44; 32],
        conflicted: false,
        revoked_through: None,
        incarnation_high_water,
    }
}

fn state(origin: RegionPresenceOrigin, revision_high_water: u64) -> RegionPresenceOriginState {
    RegionPresenceOriginState {
        origin,
        revision_high_water,
        snapshot_required: false,
    }
}

fn table(
    entries: Vec<RegionPresenceRecord>,
    origins: Vec<RegionPresenceOriginState>,
) -> RegionPresenceTable {
    RegionPresenceTable { entries, origins }
}

fn channels(origins: &[RegionPresenceOrigin]) -> Vec<RegionPresenceChannels> {
    origins
        .iter()
        .copied()
        .map(|origin| RegionPresenceChannels {
            origin,
            control_up: true,
            data_up: true,
        })
        .collect()
}

fn input<'a>(
    stream: RegionPresenceStream,
    durable_marks: &'a [RegionMarks],
    channel_states: &'a [RegionPresenceChannels],
    local_member_id: u8,
    local_gone_revision: Option<u64>,
) -> RegionPresenceInput<'a> {
    RegionPresenceInput {
        stream,
        durable_marks,
        channel_states,
        capacity: RegionPresenceCapacity {
            maximum_entries: 16,
        },
        local_member_id,
        local_gone_revision,
    }
}

fn current_stream(origin: RegionPresenceOrigin) -> RegionPresenceStream {
    RegionPresenceStream {
        origin,
        is_current: true,
    }
}

fn entry_for_owner(
    table: &RegionPresenceTable,
    identity_byte: u8,
) -> Result<&RegionPresenceRecord, String> {
    table
        .entries
        .iter()
        .find(|entry| entry.session.presence.identity == [identity_byte; 32])
        .ok_or_else(|| format!("missing owner {identity_byte}"))
}

fn gone_for(presence: RegionPresence, revision: u64) -> RegionGone {
    RegionGone {
        slot: presence.slot,
        network_id: presence.network_id,
        identity: presence.identity,
        generation: presence.generation,
        incarnation: presence.incarnation,
        reason: RegionGoneReason::Superseded,
        boot_epoch: presence.boot_epoch,
        revision,
    }
}

#[test]
fn generation_precedes_incarnation_in_presence_selection() -> Result<(), String> {
    fixture_expect("generation_before_incarnation", "higher-generation")?;
    let first = origin(2, 10);
    let second = origin(3, 20);
    let existing = presence_for(first, 0x22, 0x31, 4, 99, 1);
    let candidate = presence_for(second, 0x22, 0x32, 5, 1, 1);
    let table = table(
        vec![record(first, existing, false)],
        vec![state(first, 1), state(second, 0)],
    );
    let durable_marks = [marks(0x22, 5, 0)];
    let channel_states = channels(&[first, second]);

    let decision = decide_region_presence(
        &table,
        RegionPresenceEvent::Present(candidate),
        input(
            current_stream(second),
            &durable_marks,
            &channel_states,
            16,
            None,
        ),
    );

    let selected = entry_for_owner(&decision.table, 0x22)?;
    if selected.session.origin != second
        || selected.session.presence.generation != 5
        || selected.session.presence.incarnation != 1
        || !selected.eligible
    {
        return Err("higher generation did not win before incarnation".to_owned());
    }
    Ok(())
}

#[test]
fn higher_generation_stays_selected_when_its_required_channel_is_down() -> Result<(), String> {
    fixture_expect("higher_generation_channel_down", "selected-ineligible")?;
    let local = origin(2, 10);
    let remote = origin(3, 20);
    let existing = presence_for(local, 0x22, 0x31, 4, 99, 1);
    let candidate = presence_for(remote, 0x22, 0x32, 5, 1, 1);
    let table = table(
        vec![record(local, existing, false)],
        vec![state(local, 1), state(remote, 0)],
    );
    let durable_marks = [marks(0x22, 5, 0)];
    let channel_states = [
        RegionPresenceChannels {
            origin: local,
            control_up: true,
            data_up: true,
        },
        RegionPresenceChannels {
            origin: remote,
            control_up: true,
            data_up: false,
        },
    ];

    let decision = decide_region_presence(
        &table,
        RegionPresenceEvent::Present(candidate),
        input(
            current_stream(remote),
            &durable_marks,
            &channel_states,
            2,
            Some(2),
        ),
    );
    let expected_effects = vec![
        RegionPresenceEffect::StopAuthenticatedAcknowledgments(RegionPresenceSession {
            origin: local,
            presence: existing,
        }),
        RegionPresenceEffect::StopForwarding(RegionPresenceSession {
            origin: local,
            presence: existing,
        }),
        RegionPresenceEffect::DropQueuedOutput(RegionPresenceSession {
            origin: local,
            presence: existing,
        }),
        RegionPresenceEffect::EmitMeshGone(gone_for(existing, 2)),
    ];
    let selected = entry_for_owner(&decision.table, 0x22)?;
    if selected.session.origin != remote
        || selected.eligible
        || decision.effects != expected_effects
    {
        return Err("channel eligibility overrode higher-generation selection".to_owned());
    }
    Ok(())
}

#[test]
fn same_origin_lower_generation_cannot_replace_the_selected_session() -> Result<(), String> {
    fixture_expect("same_origin_lower_generation", "retired-lower-generation")?;
    let local = origin(2, 10);
    let existing = presence_for(local, 0x22, 0x31, 5, 1, 1);
    let candidate = presence_for(local, 0x22, 0x32, 4, 99, 2);
    let table = table(vec![record(local, existing, false)], vec![state(local, 1)]);
    let durable_marks = [marks(0x22, 5, 0)];
    let channel_states = channels(&[local]);

    let decision = decide_region_presence(
        &table,
        RegionPresenceEvent::Present(candidate),
        input(
            current_stream(local),
            &durable_marks,
            &channel_states,
            2,
            Some(3),
        ),
    );
    let expected_effects = vec![
        RegionPresenceEffect::StopAuthenticatedAcknowledgments(RegionPresenceSession {
            origin: local,
            presence: candidate,
        }),
        RegionPresenceEffect::StopForwarding(RegionPresenceSession {
            origin: local,
            presence: candidate,
        }),
        RegionPresenceEffect::DropQueuedOutput(RegionPresenceSession {
            origin: local,
            presence: candidate,
        }),
        RegionPresenceEffect::EmitMeshGone(gone_for(candidate, 3)),
    ];
    let selected = entry_for_owner(&decision.table, 0x22)?;
    if selected.session
        != (RegionPresenceSession {
            origin: local,
            presence: existing,
        })
        || !selected.eligible
        || decision.effects != expected_effects
    {
        return Err("same-origin lower generation replaced the selected session".to_owned());
    }
    Ok(())
}

#[test]
fn incarnation_precedes_member_id_in_presence_selection() -> Result<(), String> {
    fixture_expect("incarnation_before_member_id", "higher-incarnation")?;
    let lower_id = origin(1, 10);
    let higher_id = origin(2, 20);
    let existing = presence_for(lower_id, 0x22, 0x31, 5, 4, 1);
    let candidate = presence_for(higher_id, 0x22, 0x32, 5, 5, 1);
    let table = table(
        vec![record(lower_id, existing, false)],
        vec![state(lower_id, 1), state(higher_id, 0)],
    );
    let durable_marks = [marks(0x22, 5, 0)];
    let channel_states = channels(&[lower_id, higher_id]);

    let decision = decide_region_presence(
        &table,
        RegionPresenceEvent::Present(candidate),
        input(
            current_stream(higher_id),
            &durable_marks,
            &channel_states,
            16,
            None,
        ),
    );

    if entry_for_owner(&decision.table, 0x22)?.session.origin != higher_id {
        return Err("member id decided before incarnation".to_owned());
    }
    Ok(())
}

#[test]
fn durable_marks_filter_a_lower_generation_before_member_id() -> Result<(), String> {
    fixture_expect("durable_mark_filtering", "ineligible")?;
    let existing_origin = origin(2, 10);
    let candidate_origin = origin(1, 20);
    let existing = presence_for(existing_origin, 0x22, 0x31, 5, 1, 1);
    let candidate = presence_for(candidate_origin, 0x22, 0x32, 4, 99, 1);
    let table = table(
        vec![record(existing_origin, existing, false)],
        vec![state(existing_origin, 1), state(candidate_origin, 0)],
    );
    let durable_marks = [marks(0x22, 5, 0)];
    let channel_states = channels(&[existing_origin, candidate_origin]);

    let decision = decide_region_presence(
        &table,
        RegionPresenceEvent::Present(candidate),
        input(
            current_stream(candidate_origin),
            &durable_marks,
            &channel_states,
            16,
            None,
        ),
    );

    let selected = entry_for_owner(&decision.table, 0x22)?;
    if selected.session.origin != existing_origin || !selected.eligible {
        return Err("an incompatible mark displaced eligible presence".to_owned());
    }
    Ok(())
}

#[test]
fn lower_member_id_breaks_only_an_equal_eligible_state() -> Result<(), String> {
    fixture_expect("member_id_tie_break", "lower-member-id")?;
    let higher_id = origin(2, 10);
    let lower_id = origin(1, 20);
    let existing = presence_for(higher_id, 0x22, 0x31, 5, 9, 1);
    let candidate = presence_for(lower_id, 0x22, 0x32, 5, 9, 1);
    let table = table(
        vec![record(higher_id, existing, false)],
        vec![state(higher_id, 1), state(lower_id, 0)],
    );
    let durable_marks = [marks(0x22, 5, 9)];
    let channel_states = channels(&[higher_id, lower_id]);

    let decision = decide_region_presence(
        &table,
        RegionPresenceEvent::Present(candidate),
        input(
            current_stream(lower_id),
            &durable_marks,
            &channel_states,
            16,
            None,
        ),
    );

    if entry_for_owner(&decision.table, 0x22)?.session.origin != lower_id {
        return Err("lower member id did not resolve equal eligible state".to_owned());
    }
    Ok(())
}

#[test]
fn presence_entry_uses_the_authenticated_origin() -> Result<(), String> {
    fixture_expect("origin_ownership", "authenticated-origin")?;
    let authenticated = origin(2, 10);
    let presence = presence_for(authenticated, 0x22, 0x31, 5, 1, 1);
    let table = table(Vec::new(), vec![state(authenticated, 0)]);
    let durable_marks = [marks(0x22, 5, 0)];
    let channel_states = channels(&[authenticated]);

    let decision = decide_region_presence(
        &table,
        RegionPresenceEvent::Present(presence),
        input(
            current_stream(authenticated),
            &durable_marks,
            &channel_states,
            16,
            None,
        ),
    );

    if entry_for_owner(&decision.table, 0x22)?.session.origin != authenticated {
        return Err("presence was not owned by the authenticated origin".to_owned());
    }
    Ok(())
}

#[test]
fn full_owner_collision_keeps_one_selected_presence() -> Result<(), String> {
    fixture_expect("full_owner_collision", "single-winner")?;
    let first = origin(2, 10);
    let second = origin(3, 20);
    let existing = presence_for(first, 0x22, 0x31, 5, 1, 1);
    let candidate = presence_for(second, 0x22, 0x32, 5, 2, 1);
    let table = table(
        vec![record(first, existing, false)],
        vec![state(first, 1), state(second, 0)],
    );
    let durable_marks = [marks(0x22, 5, 0)];
    let channel_states = channels(&[first, second]);

    let decision = decide_region_presence(
        &table,
        RegionPresenceEvent::Present(candidate),
        input(
            current_stream(second),
            &durable_marks,
            &channel_states,
            16,
            None,
        ),
    );

    if decision.table.entries.len() != 1
        || entry_for_owner(&decision.table, 0x22)?.session.origin != second
    {
        return Err("full-owner collision retained more than one selected presence".to_owned());
    }
    Ok(())
}

#[test]
fn gone_removes_only_its_exact_originating_session() -> Result<(), String> {
    fixture_expect("exact_gone_removal", "exact-session")?;
    let first = origin(2, 10);
    let second = origin(3, 20);
    let first_presence = presence_for(first, 0x22, 0x31, 5, 4, 1);
    let second_presence = presence_for(second, 0x23, 0x32, 5, 4, 1);
    let table = table(
        vec![
            record(first, first_presence, false),
            record(second, second_presence, false),
        ],
        vec![state(first, 1), state(second, 1)],
    );
    let durable_marks = [marks(0x22, 5, 0), marks(0x23, 5, 0)];
    let channel_states = channels(&[first, second]);
    let mut nonmatching = gone_for(first_presence, 2);
    nonmatching.incarnation = 5;

    let after_nonmatching = decide_region_presence(
        &table,
        RegionPresenceEvent::Gone(nonmatching),
        input(
            current_stream(first),
            &durable_marks,
            &channel_states,
            16,
            None,
        ),
    );
    if after_nonmatching.table.entries.len() != 2 {
        return Err("nonmatching GONE removed a presence".to_owned());
    }

    let after_exact = decide_region_presence(
        &after_nonmatching.table,
        RegionPresenceEvent::Gone(gone_for(first_presence, 3)),
        input(
            current_stream(first),
            &durable_marks,
            &channel_states,
            16,
            None,
        ),
    );
    if after_exact.table.entries.len() != 1
        || entry_for_owner(&after_exact.table, 0x23)?.session
            != (RegionPresenceSession {
                origin: second,
                presence: second_presence,
            })
    {
        return Err("exact GONE did not preserve unrelated presence".to_owned());
    }
    Ok(())
}

#[test]
fn gone_high_water_prevents_an_older_present_from_resurrecting() -> Result<(), String> {
    fixture_expect("revision_high_water", "no-resurrection")?;
    let authenticated = origin(2, 10);
    let presence = presence_for(authenticated, 0x22, 0x31, 5, 4, 1);
    let table = table(
        vec![record(authenticated, presence, false)],
        vec![state(authenticated, 1)],
    );
    let durable_marks = [marks(0x22, 5, 0)];
    let channel_states = channels(&[authenticated]);

    let retired = decide_region_presence(
        &table,
        RegionPresenceEvent::Gone(gone_for(presence, 2)),
        input(
            current_stream(authenticated),
            &durable_marks,
            &channel_states,
            16,
            None,
        ),
    );
    let stale = decide_region_presence(
        &retired.table,
        RegionPresenceEvent::Present(presence),
        input(
            current_stream(authenticated),
            &durable_marks,
            &channel_states,
            16,
            None,
        ),
    );

    if !stale.table.entries.is_empty()
        || stale.disposition != keynet_proto::RegionPresenceDisposition::IgnoredStaleRevision
        || stale.table.origins[0].revision_high_water != 2
    {
        return Err("older PRESENT resurrected an exact GONE session".to_owned());
    }
    Ok(())
}

#[test]
fn stale_stream_event_is_refused_without_state_change() -> Result<(), String> {
    fixture_expect("stale_stream", "refused")?;
    let authenticated = origin(2, 10);
    let presence = presence_for(authenticated, 0x22, 0x31, 5, 4, 1);
    let table = table(
        vec![record(authenticated, presence, false)],
        vec![state(authenticated, 1)],
    );
    let durable_marks = [marks(0x22, 5, 0)];
    let channel_states = channels(&[authenticated]);
    let stale_stream = RegionPresenceStream {
        origin: authenticated,
        is_current: false,
    };
    let newer = presence_for(authenticated, 0x22, 0x32, 5, 5, 2);

    let decision = decide_region_presence(
        &table,
        RegionPresenceEvent::Present(newer),
        input(stale_stream, &durable_marks, &channel_states, 16, None),
    );

    if decision.table != table
        || !decision.effects.is_empty()
        || decision.disposition != keynet_proto::RegionPresenceDisposition::IgnoredStaleStream
    {
        return Err("stale stream event changed presence state".to_owned());
    }
    Ok(())
}

#[test]
fn boot_epoch_replacement_invalidates_routes_and_requires_snapshot() -> Result<(), String> {
    fixture_expect("epoch_replacement", "snapshot-required")?;
    let old_origin = origin(2, 10);
    let new_origin = origin(2, 11);
    let old_presence = presence_for(old_origin, 0x22, 0x31, 5, 4, 1);
    let new_presence = presence_for(new_origin, 0x22, 0x32, 5, 5, 1);
    let table = table(
        vec![record(old_origin, old_presence, false)],
        vec![state(old_origin, 1)],
    );
    let durable_marks = [marks(0x22, 5, 0)];
    let channel_states = channels(&[new_origin]);

    let decision = decide_region_presence(
        &table,
        RegionPresenceEvent::Present(new_presence),
        input(
            current_stream(new_origin),
            &durable_marks,
            &channel_states,
            16,
            None,
        ),
    );

    if !decision.table.entries.is_empty()
        || decision.table.origins.len() != 1
        || decision.table.origins[0].origin != new_origin
        || !decision.table.origins[0].snapshot_required
        || decision.disposition != keynet_proto::RegionPresenceDisposition::ReplacedEpoch
    {
        return Err("boot epoch replacement left an old route usable".to_owned());
    }
    Ok(())
}

#[test]
fn local_loser_emits_only_mesh_retirement_effects_and_keeps_marks() -> Result<(), String> {
    fixture_expect("local_loser_effects", "mesh-gone-only")?;
    fixture_expect("durable_floors_retained", "preserved")?;
    let local = origin(2, 10);
    let remote = origin(1, 20);
    let local_presence = presence_for(local, 0x22, 0x31, 5, 9, 1);
    let remote_presence = presence_for(remote, 0x22, 0x32, 5, 9, 1);
    let table = table(
        vec![record(local, local_presence, false)],
        vec![state(local, 1), state(remote, 0)],
    );
    let durable_marks = [marks(0x22, 5, 9)];
    let durable_marks_before = durable_marks;
    let channel_states = channels(&[local, remote]);

    let decision = decide_region_presence(
        &table,
        RegionPresenceEvent::Present(remote_presence),
        input(
            current_stream(remote),
            &durable_marks,
            &channel_states,
            2,
            Some(2),
        ),
    );
    let expected = vec![
        RegionPresenceEffect::StopAuthenticatedAcknowledgments(RegionPresenceSession {
            origin: local,
            presence: local_presence,
        }),
        RegionPresenceEffect::StopForwarding(RegionPresenceSession {
            origin: local,
            presence: local_presence,
        }),
        RegionPresenceEffect::DropQueuedOutput(RegionPresenceSession {
            origin: local,
            presence: local_presence,
        }),
        RegionPresenceEffect::EmitMeshGone(gone_for(local_presence, 2)),
    ];

    if decision.effects != expected
        || durable_marks != durable_marks_before
        || entry_for_owner(&decision.table, 0x22)?.session.origin != remote
    {
        return Err(
            "local supersession emitted an unexpected effect or changed durable floors".to_owned(),
        );
    }
    Ok(())
}

#[test]
fn grace_cached_presence_is_ineligible_while_a_required_channel_is_down() -> Result<(), String> {
    fixture_expect("grace_channel_down", "ineligible")?;
    let authenticated = origin(2, 10);
    let cached = presence_for(authenticated, 0x22, 0x31, 5, 4, 1);
    let unrelated = presence_for(authenticated, 0x23, 0x32, 5, 1, 2);
    let table = table(
        vec![record(authenticated, cached, true)],
        vec![state(authenticated, 1)],
    );
    let durable_marks = [marks(0x22, 5, 0), marks(0x23, 5, 0)];
    let channel_states = [RegionPresenceChannels {
        origin: authenticated,
        control_up: true,
        data_up: false,
    }];

    let decision = decide_region_presence(
        &table,
        RegionPresenceEvent::Gone(gone_for(unrelated, 2)),
        input(
            current_stream(authenticated),
            &durable_marks,
            &channel_states,
            16,
            None,
        ),
    );
    let retained = entry_for_owner(&decision.table, 0x22)?;
    if !retained.grace_cached || retained.eligible {
        return Err("grace cached presence stayed eligible without a live channel pair".to_owned());
    }
    Ok(())
}

#[test]
fn capacity_is_an_explicit_bound_on_new_presence() -> Result<(), String> {
    fixture_expect("capacity_bound", "no-growth")?;
    let first = origin(2, 10);
    let second = origin(3, 20);
    let existing = presence_for(first, 0x22, 0x31, 5, 1, 1);
    let candidate = presence_for(second, 0x23, 0x32, 5, 1, 1);
    let table = table(
        vec![record(first, existing, false)],
        vec![state(first, 1), state(second, 0)],
    );
    let durable_marks = [marks(0x22, 5, 0), marks(0x23, 5, 0)];
    let channel_states = channels(&[first, second]);
    let mut event_input = input(
        current_stream(second),
        &durable_marks,
        &channel_states,
        16,
        None,
    );
    event_input.capacity.maximum_entries = 1;

    let decision =
        decide_region_presence(&table, RegionPresenceEvent::Present(candidate), event_input);

    if decision.table.entries.len() != 1
        || entry_for_owner(&decision.table, 0x22)?.session.origin != first
        || decision.table.origins[1].revision_high_water != 1
    {
        return Err("capacity bound allowed an additional presence".to_owned());
    }
    Ok(())
}
