use keynet_proto::{
    RegionHelloExtension, RegionQuickLink, RegionQuickOwner, RegionQuickOwnerDecision,
    RegionQuickOwnerState, decide_region_quick_owner,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
};

const REGION_QUICK_OWNER_CASES: &str = "equal,equal_epoch_maximum,peer_higher_same_owner,peer_higher_other_owner,peer_higher_by_one_at_maximum,peer_lower_same_owner,peer_lower_other_owner,equal_epoch_other_owner,equal_epoch_other_owner_reverse,local_without_owner_peer_owner,local_owner_peer_legacy,neither_owner,higher_fence_persists_across_agreed_links,higher_fence_lifted_by_reload_to_highest,higher_fence_lifted_by_reload_above_highest,higher_fence_kept_by_reload_below_highest,highest_observed_epoch_never_decreases,reload_to_highest_with_other_owner_stays_fenced,local_without_owner_fence_lifted_by_reload,conflict_persists_across_agreed_links,conflict_after_agreed_link,conflict_lifted_by_reload_above,conflict_between_peers_above_local,conflict_between_peers_reset_by_higher_epoch,conflict_below_local_epoch_ignored";

/// The peer side of one step: a HELLO with or without the owner extension, or none at all.
#[derive(Clone, Copy, Debug)]
enum Peer {
    Hello(Option<RegionQuickOwner>),
    Absent,
}

#[derive(Debug)]
struct Step {
    local: Option<RegionQuickOwner>,
    peer: Peer,
    link: Option<RegionQuickLink>,
    may_serve: bool,
}

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/keynet-region-quick-v1")
}

fn owner(input: &str) -> Result<RegionQuickOwner, String> {
    let (owner, epoch) = input
        .split_once('@')
        .ok_or_else(|| format!("invalid region quick owner vector claim: {input}"))?;
    let owner = owner
        .parse()
        .map_err(|_| format!("invalid owner: {input}"))?;
    let epoch = epoch
        .parse()
        .map_err(|_| format!("invalid epoch: {input}"))?;
    RegionQuickOwner::new(owner, epoch).ok_or_else(|| format!("out-of-range claim: {input}"))
}

fn step(input: &str) -> Result<Step, String> {
    let fields = input.split('|').collect::<Vec<_>>();
    let [local, peer, link, serving] = fields.as_slice() else {
        return Err(format!("invalid region quick owner vector step: {input}"));
    };
    let local = match *local {
        "none" => None,
        claim => Some(owner(claim)?),
    };
    let peer = match *peer {
        "-" => Peer::Absent,
        "legacy" => Peer::Hello(None),
        claim => Peer::Hello(Some(owner(claim)?)),
    };
    let link = match *link {
        "-" => None,
        "agreed" => Some(RegionQuickLink::Agreed),
        "inactive" => Some(RegionQuickLink::Inactive),
        "mismatched" => Some(RegionQuickLink::Mismatched),
        _ => return Err(format!("invalid link: {input}")),
    };
    if matches!(peer, Peer::Absent) != link.is_none() {
        return Err(format!("link state without a peer HELLO: {input}"));
    }
    let may_serve = match *serving {
        "serve" => true,
        "fenced" => false,
        _ => return Err(format!("invalid serving state: {input}")),
    };
    Ok(Step {
        local,
        peer,
        link,
        may_serve,
    })
}

fn vectors() -> Result<BTreeMap<String, Vec<Step>>, String> {
    let text = fs::read_to_string(fixture_root().join("region_quick_owner.vec"))
        .map_err(|error| error.to_string())?;
    let mut output = BTreeMap::new();
    for block in text.split("\n\n").filter(|block| !block.trim().is_empty()) {
        let mut case = None;
        let mut steps = BTreeMap::new();
        for line in block.lines().filter(|line| !line.starts_with('#')) {
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| "invalid region quick owner vector line".to_owned())?;
            if key == "case" {
                if case.replace(value.to_owned()).is_some() {
                    return Err("duplicate region quick owner case field".to_owned());
                }
                continue;
            }
            let index = key
                .strip_prefix("step")
                .and_then(|index| index.parse::<usize>().ok())
                .ok_or_else(|| format!("invalid region quick owner vector field: {key}"))?;
            if steps.insert(index, step(value)?).is_some() {
                return Err(format!("duplicate region quick owner step: {key}"));
            }
        }
        let case = case.ok_or_else(|| "missing region quick owner case".to_owned())?;
        if steps.keys().copied().ne(1..=steps.len()) || steps.is_empty() {
            return Err(format!("region quick owner steps are not 1..n: {case}"));
        }
        if output
            .insert(case.clone(), steps.into_values().collect())
            .is_some()
        {
            return Err(format!("duplicate region quick owner case: {case}"));
        }
    }
    Ok(output)
}

fn claim(owner: u8, epoch: u64) -> Result<RegionQuickOwner, String> {
    RegionQuickOwner::new(owner, epoch).ok_or_else(|| format!("invalid claim {owner}@{epoch}"))
}

fn expect(
    decision: RegionQuickOwnerDecision,
    link: RegionQuickLink,
    may_serve: bool,
    label: &str,
) -> Result<(), String> {
    if decision != (RegionQuickOwnerDecision { link, may_serve }) {
        return Err(format!(
            "{label}: expected {link:?} with may_serve={may_serve}, got {decision:?}"
        ));
    }
    Ok(())
}

#[test]
fn owner_claims_accept_only_configurable_values() -> Result<(), String> {
    // The claim range restates the HELLO extension validation: owner 1..=16, epoch at least 1.
    for (owner, epoch, valid) in [
        (1, 1, true),
        (16, u64::MAX, true),
        (0, 1, false),
        (17, 1, false),
        (2, 0, false),
    ] {
        let claim = RegionQuickOwner::new(owner, epoch);
        if claim.is_some() != valid {
            return Err(format!("claim {owner}@{epoch} validity is not {valid}"));
        }
        if let Some(claim) = claim
            && (claim.owner() != owner || claim.epoch() != epoch)
        {
            return Err(format!("claim {owner}@{epoch} did not keep its values"));
        }
    }
    let extension = RegionHelloExtension {
        capabilities: 1,
        quick_owner: 2,
        quick_owner_epoch: 5,
    };
    if RegionQuickOwner::from_extension(extension) != Some(claim(2, 5)?) {
        return Err("extension claim differs from its owner and epoch".to_owned());
    }
    Ok(())
}

#[test]
fn sealed_region_quick_owner_vectors_match_the_declared_cases() -> Result<(), String> {
    let vectors = vectors()?;
    let expected = REGION_QUICK_OWNER_CASES
        .split(',')
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if vectors.keys().cloned().collect::<BTreeSet<_>>() != expected {
        return Err("sealed region quick owner inventory changed".to_owned());
    }
    for (case, steps) in &vectors {
        let mut state = RegionQuickOwnerState::default();
        for (index, step) in steps.iter().enumerate() {
            let label = format!("{case} step{}", index + 1);
            match step.peer {
                Peer::Hello(peer) => {
                    let decision = decide_region_quick_owner(&mut state, step.local, peer);
                    let link = step
                        .link
                        .ok_or_else(|| format!("{label}: missing link state"))?;
                    expect(decision, link, step.may_serve, &label)?;
                }
                Peer::Absent => {
                    if state.may_serve(step.local) != step.may_serve {
                        return Err(format!("{label}: may_serve is not {}", step.may_serve));
                    }
                }
            }
            // The serving permission is a function of the state and the local claim alone.
            if state.may_serve(step.local) != step.may_serve {
                return Err(format!("{label}: state query disagrees with the decision"));
            }
        }
    }
    Ok(())
}

#[test]
fn fence_from_a_higher_epoch_persists_until_reload_reaches_it() -> Result<(), String> {
    let mut state = RegionQuickOwnerState::default();
    let local = Some(claim(2, 5)?);
    expect(
        decide_region_quick_owner(&mut state, local, Some(claim(3, 7)?)),
        RegionQuickLink::Mismatched,
        false,
        "higher epoch",
    )?;
    if state.highest_observed_epoch() != 7 {
        return Err("highest observed epoch is not 7".to_owned());
    }
    for _ in 0..3 {
        expect(
            decide_region_quick_owner(&mut state, local, local),
            RegionQuickLink::Agreed,
            false,
            "agreed link after fence",
        )?;
    }
    if state.may_serve(Some(claim(3, 6)?)) {
        return Err("a reload below the highest epoch lifted the fence".to_owned());
    }
    if !state.may_serve(Some(claim(3, 7)?)) {
        return Err("a reload to the highest epoch kept the fence".to_owned());
    }
    Ok(())
}

#[test]
fn restart_with_a_new_state_lifts_every_fence() -> Result<(), String> {
    let local = Some(claim(2, 5)?);
    let mut state = RegionQuickOwnerState::default();
    decide_region_quick_owner(&mut state, local, Some(claim(3, 7)?));
    decide_region_quick_owner(&mut state, local, Some(claim(3, 5)?));
    if state.may_serve(local) {
        return Err("the fenced state still serves".to_owned());
    }
    let restarted = RegionQuickOwnerState::default();
    if !restarted.may_serve(local) || restarted.highest_observed_epoch() != 0 {
        return Err("a new state carried a fence".to_owned());
    }
    Ok(())
}

#[test]
fn same_epoch_with_different_owners_fences_both_members() -> Result<(), String> {
    let first = Some(claim(2, 5)?);
    let second = Some(claim(3, 5)?);
    let mut first_state = RegionQuickOwnerState::default();
    let mut second_state = RegionQuickOwnerState::default();
    expect(
        decide_region_quick_owner(&mut first_state, first, second),
        RegionQuickLink::Mismatched,
        false,
        "first member",
    )?;
    expect(
        decide_region_quick_owner(&mut second_state, second, first),
        RegionQuickLink::Mismatched,
        false,
        "second member",
    )?;
    // A third member agreeing with either side does not lift the conflict.
    expect(
        decide_region_quick_owner(&mut first_state, first, first),
        RegionQuickLink::Agreed,
        false,
        "first member with an agreeing peer",
    )?;
    expect(
        decide_region_quick_owner(&mut second_state, second, second),
        RegionQuickLink::Agreed,
        false,
        "second member with an agreeing peer",
    )?;
    Ok(())
}

#[test]
fn every_owner_and_epoch_pair_is_decided_consistently() -> Result<(), String> {
    // An exhaustive sweep over a small grid: the link and the permission follow D4 for every
    // combination of local and peer owner (including none and the legacy HELLO) and epoch.
    let mut claims = vec![None];
    for owner in [1, 2, 16] {
        for epoch in [1, 2, 3, u64::MAX] {
            claims.push(Some(claim(owner, epoch)?));
        }
    }
    for local in &claims {
        for peer in &claims {
            let mut state = RegionQuickOwnerState::default();
            let decision = decide_region_quick_owner(&mut state, *local, *peer);
            let link = match (local, peer) {
                (None, None) => RegionQuickLink::Inactive,
                (Some(local), Some(peer)) if local == peer => RegionQuickLink::Agreed,
                _ => RegionQuickLink::Mismatched,
            };
            let local_epoch = local.map_or(0, |claim| claim.epoch());
            let may_serve = match peer {
                None => true,
                Some(peer) => {
                    peer.epoch() < local_epoch
                        || (peer.epoch() == local_epoch && Some(*peer) == *local)
                }
            };
            expect(
                decision,
                link,
                may_serve,
                &format!("local {local:?} peer {peer:?}"),
            )?;
        }
    }
    Ok(())
}
