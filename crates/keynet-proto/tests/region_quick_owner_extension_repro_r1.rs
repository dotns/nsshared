//! A HELLO that carries the owner extension is never the legacy HELLO, whatever its values.

use keynet_proto::{
    RegionHelloExtension, RegionQuickOwner, RegionQuickOwnerState, decide_region_quick_owner,
};

#[test]
fn an_out_of_range_extension_does_not_read_as_a_legacy_hello() -> Result<(), String> {
    let local = RegionQuickOwner::new(2, 5).ok_or("invalid local claim")?;
    // The peer presents an epoch above the local one with an owner outside 1..=16.
    let extension = RegionHelloExtension {
        capabilities: 1,
        quick_owner: 0,
        quick_owner_epoch: 9,
    };
    let peer = RegionQuickOwner::from_extension(extension);
    let mut state = RegionQuickOwnerState::default();
    let decision = decide_region_quick_owner(&mut state, Some(local), peer);
    if decision.may_serve {
        return Err(format!(
            "an extension presenting epoch 9 was read as a legacy HELLO: {decision:?}, \
             highest observed epoch {}",
            state.highest_observed_epoch()
        ));
    }
    Ok(())
}
