use blake2::{
    Blake2s, Digest,
    digest::consts::{U4, U15, U20},
};

use super::{Error, OverlayAddresses};

pub fn member_id(signing_pub: &[u8; 32]) -> [u8; 20] {
    Blake2s::<U20>::digest(signing_pub).into()
}

pub fn fingerprint(public_key: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(member_id(public_key)))
}

pub fn parse_fingerprint(value: &str) -> Result<[u8; 20], Error> {
    let hex = value
        .strip_prefix("0x")
        .ok_or(Error::Payload("fingerprint prefix"))?;
    if hex.len() != 40
        || !hex
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(Error::Payload("canonical fingerprint"));
    }
    let mut id = [0; 20];
    hex::decode_to_slice(hex, &mut id).map_err(|_| Error::Payload("fingerprint"))?;
    Ok(id)
}

pub fn overlay_ipv6(wg_pub: &[u8; 32]) -> [u8; 16] {
    let mut hash = Blake2s::<U15>::new();
    hash.update(b"nsmesh-ipv6-v1\0");
    hash.update(wg_pub);
    let mut address = [0; 16];
    address[0] = 0xfd;
    address[1..].copy_from_slice(&hash.finalize());
    address
}

pub fn overlay_ipv4(wg_pub: &[u8; 32], salt: u32) -> Result<[u8; 4], Error> {
    let mut hash = Blake2s::<U4>::new();
    hash.update(b"nsmesh-ipv4-v1\0");
    hash.update(wg_pub);
    hash.update(salt.to_be_bytes());
    let digest = hash.finalize();
    if matches!((digest[2], digest[3]), (0, 0) | (255, 255)) {
        return Err(Error::Payload("reserved overlay IPv4"));
    }
    Ok([100, 100, digest[2], digest[3]])
}

pub fn derive_overlay_addresses(wg_pub: &[u8; 32], salt: u32) -> Result<OverlayAddresses, Error> {
    Ok(OverlayAddresses {
        v4: overlay_ipv4(wg_pub, salt)?,
        v4_salt: u64::from(salt),
        v6: overlay_ipv6(wg_pub),
    })
}

pub fn verify_overlay_addresses(
    wg_pub: &[u8; 32],
    addresses: &OverlayAddresses,
) -> Result<(), Error> {
    let salt = u32::try_from(addresses.v4_salt).map_err(|_| Error::Payload("IPv4 salt width"))?;
    if &derive_overlay_addresses(wg_pub, salt)? != addresses {
        return Err(Error::Payload("overlay address binding"));
    }
    Ok(())
}

/// Test at most four consecutive salts; the caller supplies its own collision inventory.
pub fn allocate_overlay_addresses(
    wg_pub: &[u8; 32],
    first_salt: u32,
    mut occupied: impl FnMut(&OverlayAddresses) -> bool,
) -> Result<OverlayAddresses, Error> {
    for offset in 0..4 {
        let salt = first_salt
            .checked_add(offset)
            .ok_or(Error::Payload("IPv4 salt exhausted"))?;
        if let Ok(candidate) = derive_overlay_addresses(wg_pub, salt)
            && !occupied(&candidate)
        {
            return Ok(candidate);
        }
    }
    Err(Error::Payload("overlay address candidates exhausted"))
}

pub fn must_yield_collision(
    own_incarnation: u64,
    own_signing_key: &[u8; 32],
    other_incarnation: u64,
    other_signing_key: &[u8; 32],
) -> bool {
    (own_incarnation, own_signing_key) > (other_incarnation, other_signing_key)
}
