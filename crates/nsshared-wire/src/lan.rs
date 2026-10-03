//! IPv4-embedding LAN prefixes published by nodes (next §4.1).
//!
//! `lan6(I, subnet_id) = fd ‖ BLAKE2s(out = 9, key = "ns-lan-addr-v2")(I ‖ subnet_id_be16)
//! ‖ 0x0000 ‖ IPv4`: 8 + 72 + 16 bits form a `/96` prefix and the low 32 bits carry the
//! IPv4 address, RFC 6052 style (next §4.1 line 75 and the label table row at line 83,
//! docs pin `957de97a79f7`). This layout was confirmed by the protocol owner and fixes a
//! defect in earlier text of that section.

use crate::{
    constants::{ADDRESS_PREFIX, LAN_ADDR_LABEL},
    identity::{Identity, keyed_blake2s},
};
use blake2::digest::consts::U9;
use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

/// Prefix length of a published LAN prefix, 96 bits (next §4.1).
pub const LAN_PREFIX_LEN: u8 = 96;

/// Mask selecting the `/96` prefix bits of an address (next §4.1).
const PREFIX_MASK: u128 = !0 << 32;

/// A published LAN prefix `lan6(I, subnet_id)/96` (next §4.1).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Lan6Prefix([u8; 16]);

impl Lan6Prefix {
    /// Derives `fd ‖ BLAKE2s(out = 9, key = "ns-lan-addr-v2")(I ‖ subnet_id_be16) ‖ 0x0000`
    /// for a node-local `subnet_id` (next §4.1).
    #[must_use]
    pub fn derive(identity: &Identity, subnet_id: u16) -> Self {
        let digest: [u8; 9] =
            keyed_blake2s::<U9>(LAN_ADDR_LABEL, &[identity, &subnet_id.to_be_bytes()]).into();
        // Bytes 10..16 (the 0x0000 pad and the IPv4 slot) stay zero.
        let mut prefix = [0_u8; 16];
        prefix[0] = ADDRESS_PREFIX;
        for (slot, byte) in prefix.iter_mut().skip(1).zip(digest) {
            *slot = byte;
        }
        Self(prefix)
    }

    /// Returns the prefix bytes with the low 32 bits zero (next §4.1).
    #[must_use]
    pub const fn bytes(&self) -> [u8; 16] {
        self.0
    }

    /// Returns the prefix as an address with the low 32 bits zero (next §4.1).
    #[must_use]
    pub const fn addr(&self) -> Ipv6Addr {
        Ipv6Addr::from_octets(self.0)
    }

    /// Returns the prefix length, 96 (next §4.1).
    #[must_use]
    pub const fn prefix_len(&self) -> u8 {
        LAN_PREFIX_LEN
    }

    /// Embeds an IPv4 address into the low 32 bits of the prefix (next §4.1).
    #[must_use]
    pub fn embed(&self, ipv4: Ipv4Addr) -> Ipv6Addr {
        Ipv6Addr::from(u128::from_be_bytes(self.0) | u128::from(u32::from(ipv4)))
    }

    /// Returns the embedded IPv4 address, or `None` when `address` lies outside this
    /// prefix (next §4.1).
    #[must_use]
    pub fn extract(&self, address: Ipv6Addr) -> Option<Ipv4Addr> {
        if !self.contains(address) {
            return None;
        }
        u32::try_from(u128::from(address) & !PREFIX_MASK)
            .ok()
            .map(Ipv4Addr::from)
    }

    /// Returns true when `address` lies in this `/96` prefix (next §4.1).
    #[must_use]
    pub fn contains(&self, address: Ipv6Addr) -> bool {
        u128::from(address) & PREFIX_MASK == u128::from_be_bytes(self.0)
    }
}

impl fmt::Display for Lan6Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr(), LAN_PREFIX_LEN)
    }
}
