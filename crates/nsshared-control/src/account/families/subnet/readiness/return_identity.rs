use crate::account::{AccountError, codec::require, subnet::SubnetPrefix};
use blake2::{
    Blake2sMac,
    digest::{KeyInit, Mac, consts::U3},
};
use std::net::{IpAddr, Ipv6Addr};

/// Derives the existing fixed consumer /128 return identity; collisions still require refusal.
/// # Errors
/// Refuses a noncanonical mapping, wrong reserved subnet or exhausted alias candidates.
pub fn consumer_return_identity(
    identity: &[u8; 32],
    mapped: SubnetPrefix,
) -> Result<Ipv6Addr, AccountError> {
    mapped.validate().map_err(super::field)?;
    let IpAddr::V6(address) = mapped.address else {
        return Err(AccountError::Field);
    };
    let mut address = address.octets();
    require((96..=128).contains(&mapped.length) && address[0] == 0xfd && address[6..8] == [0, 1])?;
    for index in 0..16 {
        let mut hash = Blake2sMac::<U3>::new_from_slice(b"ns-alias4-v2").map_err(super::field)?;
        hash.update(identity);
        hash.update(&[4, index]);
        let hash = hash.finalize().into_bytes();
        let alias =
            0x6440_0000 | ((u32::from_be_bytes([0, hash[0], hash[1], hash[2]]) >> 2) % (1 << 21));
        if alias != 0x6440_0001 {
            address[6..8].copy_from_slice(&[0, 2]);
            address[8..12].fill(0);
            address[12..16].copy_from_slice(&alias.to_be_bytes());
            return Ok(Ipv6Addr::from(address));
        }
    }
    Err(AccountError::Field)
}
