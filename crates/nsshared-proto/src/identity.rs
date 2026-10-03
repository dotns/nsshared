//! Identity-derived node IDs and address groups (quick-v2 §2.1-§2.2).

use crate::constants::{
    ADDRESS_GROUP_PREFIX_LEN, ADDRESS_PREFIX, NODE_ADDR_LABEL, NODE_ID_BYTES, NODE_ID_LABEL,
    NODE_ID_TEXT_LEN,
};
use blake2::{
    Blake2sMac,
    digest::{
        KeyInit, Mac,
        array::{Array, ArraySize},
        consts::{U12, U15, U32},
        typenum::{IsLessOrEqual, True},
    },
};
use std::{fmt, net::Ipv6Addr, str::FromStr};
use thiserror::Error;

/// A raw Ed25519 identity public key `I` (quick-v2 §2.1).
pub type Identity = [u8; 32];

// Keyed BLAKE2s accepts keys of at most 32 bytes; every label must fit.
const _: () = assert!(NODE_ID_LABEL.len() <= 32);
const _: () = assert!(NODE_ADDR_LABEL.len() <= 32);

/// Keyed BLAKE2s over the concatenation of `parts`, keyed by an ASCII label (quick-v2 §2.2).
pub(crate) fn keyed_blake2s<N>(label: &[u8], parts: &[&[u8]]) -> Array<u8, N>
where
    N: ArraySize + IsLessOrEqual<U32, Output = True>,
{
    // Unreachable: keying only fails for keys longer than 32 bytes, excluded above.
    let Ok(mut mac) = <Blake2sMac<N> as KeyInit>::new_from_slice(label) else {
        return Array::default();
    };
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes()
}

/// A node ID: `BLAKE2s(out = 12, key = "ns-node-id-v2")(I)` (quick-v2 §2.2).
///
/// Text form is lowercase unpadded RFC 4648 base32 of exactly 20 characters; the raw
/// 12 bytes double as the relay slot (quick-v2 §8.1).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NodeId([u8; NODE_ID_BYTES]);

impl NodeId {
    /// Derives the node ID of an identity (quick-v2 §2.2).
    #[must_use]
    pub fn derive(identity: &Identity) -> Self {
        Self(keyed_blake2s::<U12>(NODE_ID_LABEL, &[identity]).into())
    }

    /// Wraps raw node ID bytes, e.g. a relay slot (quick-v2 §2.2, §8.1).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; NODE_ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the raw 12 bytes, which are also the relay slot (quick-v2 §2.2, §8.1).
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; NODE_ID_BYTES] {
        &self.0
    }

    /// Returns true when all 12 bytes are zero (quick-v2 §8.1).
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&byte| byte == 0)
    }

    /// The 96 node ID bits followed by four zero bits, as a 100-bit integer.
    fn text_bits(&self) -> u128 {
        self.0
            .iter()
            .fold(0_u128, |acc, &byte| (acc << 8) | u128::from(byte))
            << 4
    }
}

/// A rejected node ID text form (quick-v2 §2.2).
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum NodeIdParseError {
    /// The text contains `=` padding.
    #[error("node ID must not be padded")]
    Padding,
    /// The text contains an uppercase letter.
    #[error("node ID must be lowercase")]
    Uppercase,
    /// The text is not exactly 20 bytes long.
    #[error("node ID must be {NODE_ID_TEXT_LEN} characters, got {0} bytes")]
    Length(usize),
    /// The text contains a byte outside the base32 alphabet `a-z2-7`.
    #[error("node ID contains a non-base32 byte {0:#04x}")]
    InvalidCharacter(u8),
    /// The final four bits of the last character are not zero.
    #[error("node ID has non-zero trailing bits")]
    NonZeroTrailingBits,
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bits = self.text_bits();
        for index in (0..NODE_ID_TEXT_LEN).rev() {
            let value = ((bits >> (5 * index)) & 0x1f) as u8;
            let symbol = if value < 26 {
                b'a' + value
            } else {
                b'2' + (value - 26)
            };
            fmt::Write::write_char(f, char::from(symbol))?;
        }
        Ok(())
    }
}

impl FromStr for NodeId {
    type Err = NodeIdParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text.contains('=') {
            return Err(NodeIdParseError::Padding);
        }
        if text.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(NodeIdParseError::Uppercase);
        }
        if text.len() != NODE_ID_TEXT_LEN {
            return Err(NodeIdParseError::Length(text.len()));
        }
        let mut bits = 0_u128;
        for byte in text.bytes() {
            let value = match byte {
                b'a'..=b'z' => byte - b'a',
                b'2'..=b'7' => byte - b'2' + 26,
                _ => return Err(NodeIdParseError::InvalidCharacter(byte)),
            };
            bits = (bits << 5) | u128::from(value);
        }
        if bits & 0xf != 0 {
            return Err(NodeIdParseError::NonZeroTrailingBits);
        }
        let bits = bits >> 4;
        let mut bytes = [0_u8; NODE_ID_BYTES];
        for (index, byte) in bytes.iter_mut().rev().enumerate() {
            *byte = (bits >> (8 * index)) as u8;
        }
        Ok(Self(bytes))
    }
}

/// A node address group `fd ‖ g ‖ m` with `m` cleared, i.e. `N6(I)/127` (quick-v2 §2.2).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AddressGroup([u8; 16]);

impl AddressGroup {
    /// Derives `g = BLAKE2s(out = 15, key = "ns-node-addr-v2")(I) >> 1` and its group (quick-v2 §2.2).
    #[must_use]
    pub fn derive(identity: &Identity) -> Self {
        let digest: [u8; 15] = keyed_blake2s::<U15>(NODE_ADDR_LABEL, &[identity]).into();
        // `fd ‖ (digest >> 1) ‖ m` keeps the top 119 digest bits in place; the
        // final digest bit is replaced by the mode bit.
        let mut address = [0_u8; 16];
        address[0] = ADDRESS_PREFIX;
        for (slot, byte) in address.iter_mut().skip(1).zip(digest) {
            *slot = byte;
        }
        Self::from_bytes(address)
    }

    /// Normalises any address bytes to their group by clearing the final bit (quick-v2 §2.2).
    #[must_use]
    pub const fn from_bytes(mut address: [u8; 16]) -> Self {
        address[15] &= !1;
        Self(address)
    }

    /// Normalises any address to its group by clearing the final bit (quick-v2 §2.2).
    #[must_use]
    pub const fn from_address(address: Ipv6Addr) -> Self {
        Self::from_bytes(address.octets())
    }

    /// Returns true when `address` lies in this `/127` group (quick-v2 §2.2).
    #[must_use]
    pub fn contains(&self, address: Ipv6Addr) -> bool {
        Self::from_address(address) == *self
    }

    /// Returns the native IPv6 service address bytes `N6 = fd ‖ g ‖ 0` (quick-v2 §2.2).
    #[must_use]
    pub const fn n6_bytes(&self) -> [u8; 16] {
        self.0
    }

    /// Returns the IPv4 service address bytes `N4 = fd ‖ g ‖ 1` (quick-v2 §2.2).
    #[must_use]
    pub const fn n4_bytes(&self) -> [u8; 16] {
        let mut address = self.0;
        address[15] |= 1;
        address
    }

    /// Returns the native IPv6 service address `N6` (quick-v2 §2.2).
    #[must_use]
    pub const fn n6(&self) -> Ipv6Addr {
        Ipv6Addr::from_octets(self.n6_bytes())
    }

    /// Returns the IPv4 service address `N4` (quick-v2 §2.2).
    #[must_use]
    pub const fn n4(&self) -> Ipv6Addr {
        Ipv6Addr::from_octets(self.n4_bytes())
    }

    /// Returns the group prefix length, 127 (quick-v2 §2.2).
    #[must_use]
    pub const fn prefix_len(&self) -> u8 {
        ADDRESS_GROUP_PREFIX_LEN
    }
}

impl fmt::Display for AddressGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.n6(), ADDRESS_GROUP_PREFIX_LEN)
    }
}

/// An identity together with its derived address group, as kept in a peer table
/// (quick-v2 §2.2).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct GroupOwner {
    /// The full identity `I`.
    pub identity: Identity,
    /// The address group derived from `identity`.
    pub group: AddressGroup,
}

impl GroupOwner {
    /// Derives the address group of an identity (quick-v2 §2.2).
    #[must_use]
    pub fn derive(identity: &Identity) -> Self {
        Self {
            identity: *identity,
            group: AddressGroup::derive(identity),
        }
    }
}

/// A candidate peer whose address group is already owned by another identity
/// (`address_conflict`, quick-v2 §2.2).
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("address_conflict: group {group} is already owned by another identity")]
pub struct AddressConflict {
    /// The full identity that already owns the group.
    pub identity: Identity,
    /// The contested address group.
    pub group: AddressGroup,
}

/// Checks a candidate peer against the local node and the installed peers before
/// installation, returning the candidate with its group (quick-v2 §2.2).
///
/// A candidate is rejected when its group equals the group of `own` or of an existing
/// peer with a different identity; an identical identity is not a conflict.
///
/// # Errors
///
/// [`AddressConflict`] carrying the full identity that already owns the group.
pub fn check_address_conflict<'a>(
    own: &'a GroupOwner,
    candidate: &Identity,
    peers: impl IntoIterator<Item = &'a GroupOwner>,
) -> Result<GroupOwner, AddressConflict> {
    let candidate = GroupOwner::derive(candidate);
    for existing in std::iter::once(own).chain(peers) {
        if existing.identity != candidate.identity && existing.group == candidate.group {
            return Err(AddressConflict {
                identity: existing.identity,
                group: candidate.group,
            });
        }
    }
    Ok(candidate)
}
