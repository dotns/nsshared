//! Registration credentials attest existing membership without changing the compact state.

use crate::envelope::ControlEnvelope;

use super::{
    CompactState, Error, Register, Vouch, encode_udp, member_id, validate_live_credential,
    verify_request,
};

impl CompactState {
    /// Validate a supplied vouch against this complete, trusted current state.
    ///
    /// This never admits an absent member or changes sequence, digest, or eviction watermarks.
    /// Normal registration of a current member does not require a vouch. A caller receiving
    /// one must validate it even if the target already matches its current membership.
    /// The runtime separately owns replay admission, carrier binding and authenticated activity.
    pub fn verify_registration_vouch(
        &self,
        registration: &ControlEnvelope,
        now: u64,
    ) -> Result<(), Error> {
        self.validate()?;
        if registration.api != Register::API {
            return Err(Error::Payload("vouch requires registration"));
        }
        verify_request(registration, now)?;
        encode_udp(&registration.to_cbor()?)?;
        let register = Register::decode(&registration.payload)?;
        let raw = register
            .vouch
            .as_ref()
            .ok_or(Error::Payload("vouch missing"))?;
        let credential = ControlEnvelope::from_cbor(raw)?;
        let vouch = Vouch::verify_historical(&credential)?;
        validate_live_credential(vouch.issued_at, vouch.expires_at, now, vouch.expires_at)?;
        if register.network_pub != self.network_pub
            || vouch.network_pub != self.network_pub
            || vouch.member_id != member_id(&registration.machine_key_pub)
            || vouch.member_wg != register.wg_pub
            || vouch.incarnation != register.member_incarnation
            || vouch.register_nonce != registration.nonce
        {
            return Err(Error::Payload("vouch registration binding"));
        }
        let member = self
            .members
            .get(&registration.machine_key_pub)
            .ok_or(Error::Payload("vouch target is not a current member"))?;
        if member.wg_pub != register.wg_pub || member.incarnation != register.member_incarnation {
            return Err(Error::Payload("vouch target incarnation or WG key"));
        }
        if !self.members.contains_key(&credential.machine_key_pub)
            || (!self.admins.is_empty() && !self.admins.contains(&credential.machine_key_pub))
        {
            return Err(Error::Payload("vouch signer is not currently entitled"));
        }
        Ok(())
    }
}
