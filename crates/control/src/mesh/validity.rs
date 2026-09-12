use super::Error;
use crate::envelope::ControlEnvelope;

/// Check signed structural time bounds, including for historical records.
pub fn validate_lifetime(issued_at: u64, expires_at: u64) -> Result<(), Error> {
    let latest = issued_at.checked_add(60).ok_or(Error::Lifetime)?;
    if expires_at <= issued_at || expires_at > latest {
        return Err(Error::Lifetime);
    }
    Ok(())
}

/// Check first execution without extending expiry by the clock-skew window.
pub fn validate_live_credential(
    issued_at: u64,
    expires_at: u64,
    now: u64,
    request_deadline: u64,
) -> Result<(), Error> {
    validate_lifetime(issued_at, expires_at)?;
    if now.abs_diff(issued_at) > 60 || now >= expires_at || expires_at > request_deadline {
        return Err(Error::Expired);
    }
    Ok(())
}

fn validate_identity(envelope: &ControlEnvelope) -> Result<(), Error> {
    if envelope.machine_id.is_some()
        || !envelope.api.starts_with("mesh.")
        || envelope.api == "mesh.cookie"
    {
        return Err(Error::Identity);
    }
    Ok(())
}

/// Verify a live request. Replay and operation deduplication belong to the owner.
pub fn verify_request(envelope: &ControlEnvelope, now: u64) -> Result<(), Error> {
    validate_identity(envelope)?;
    envelope.verify_request(now)?;
    Ok(())
}

/// Verify original signed bytes without applying today's nonce or clock window.
/// Callers must separately check record fields, original lifetime and authority.
pub fn verify_historical_request(envelope: &ControlEnvelope) -> Result<(), Error> {
    validate_identity(envelope)?;
    envelope.verify_request(envelope.ts)?;
    Ok(())
}

/// Authenticate a live relay response against the saved relay key.
pub fn verify_response(
    envelope: &ControlEnvelope,
    now: u64,
    relay_key: &[u8; 32],
) -> Result<(), Error> {
    validate_identity(envelope)?;
    envelope.verify_response(now, relay_key)?;
    Ok(())
}
