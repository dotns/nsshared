#![forbid(unsafe_code)]
#![deny(missing_docs, clippy::panic, clippy::unwrap_used, clippy::expect_used)]

//! Synchronous Keynet v0.4 address, identity-label, and local-conflict primitives.

use blake2::{
    Blake2sMac,
    digest::{
        KeyInit, Mac,
        consts::{U12, U15},
    },
};
use std::net::Ipv6Addr;

/// The Keynet address-format version defined by design section 13.6.
pub const ADDRESS_VERSION: u8 = 1;
const ADDRESS_KEY: &[u8] = b"keynet-addr-v1";
const IDENTITY_KEY: &[u8] = b"keynet-id-v1";
const ADDRESS_DIGEST_BYTES: usize = 15;
const IDENTITY_DIGEST_BYTES: usize = 12;
const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// A Keynet network identifier from design sections 3.2 and 13.6.
pub type NetworkId = [u8; 32];
/// A Keynet identity public key from design sections 3.2 and 13.4.
pub type Identity = [u8; 32];

/// An initialization failure for a fixed-size BLAKE2s derivation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DerivationError {
    /// The requested BLAKE2s variable-output size was rejected by the implementation.
    InvalidOutputSize,
}

/// One normalized Keynet address group from design sections 3.2 and 3.4.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AddressGroup([u8; 16]);

impl AddressGroup {
    /// Normalizes an address into its group by clearing the final mode bit (§3.2).
    #[must_use]
    pub fn from_address_bytes(address: [u8; 16]) -> Self {
        Self(group_bytes(address))
    }
    /// Returns the native IPv6 service address with mode zero (§3.2).
    #[must_use]
    pub fn n6_bytes(self) -> [u8; 16] {
        self.0
    }
    /// Returns the translated IPv4-service address with mode one (§3.2).
    #[must_use]
    pub fn n4_bytes(self) -> [u8; 16] {
        n4_bytes_from_group(self.0)
    }
    /// Returns the native IPv6 service address as an `Ipv6Addr` (§3.2).
    #[must_use]
    pub fn n6(self) -> Ipv6Addr {
        Ipv6Addr::from(self.n6_bytes())
    }
    /// Returns the translated IPv4-service address as an `Ipv6Addr` (§3.2).
    #[must_use]
    pub fn n4(self) -> Ipv6Addr {
        Ipv6Addr::from(self.n4_bytes())
    }
    /// Returns the normalized sixteen-byte group representation (§3.2).
    #[must_use]
    pub fn into_bytes(self) -> [u8; 16] {
        self.0
    }
}

/// Derives the address group for a network and identity using section 3.2.
pub fn derive_address_group(
    network_id: &NetworkId,
    identity: &Identity,
) -> Result<AddressGroup, DerivationError> {
    let mut input = [0_u8; 65];
    input[0] = ADDRESS_VERSION;
    input[1..33].copy_from_slice(network_id);
    input[33..].copy_from_slice(identity);
    let digest = address_digest(&input)?;
    let mut address = [0_u8; 16];
    address[0] = 0xfd;
    address[1..].copy_from_slice(&digest);
    Ok(AddressGroup::from_address_bytes(address))
}

/// Derives the mode-zero N6 address bytes for a network and identity (§3.2).
pub fn n6_bytes(network_id: &NetworkId, identity: &Identity) -> Result<[u8; 16], DerivationError> {
    Ok(derive_address_group(network_id, identity)?.n6_bytes())
}
/// Derives the mode-one N4 address bytes for a network and identity (§3.2).
pub fn n4_bytes(network_id: &NetworkId, identity: &Identity) -> Result<[u8; 16], DerivationError> {
    Ok(derive_address_group(network_id, identity)?.n4_bytes())
}
/// Derives the mode-zero N6 address for a network and identity (§3.2).
pub fn n6(network_id: &NetworkId, identity: &Identity) -> Result<Ipv6Addr, DerivationError> {
    Ok(derive_address_group(network_id, identity)?.n6())
}
/// Derives the mode-one N4 address for a network and identity (§3.2).
pub fn n4(network_id: &NetworkId, identity: &Identity) -> Result<Ipv6Addr, DerivationError> {
    Ok(derive_address_group(network_id, identity)?.n4())
}

/// Clears the mode bit of a raw sixteen-byte Keynet address (§3.2).
#[must_use]
pub fn group_bytes(mut address: [u8; 16]) -> [u8; 16] {
    address[15] &= !1;
    address
}
/// Clears the mode bit of an IPv6 Keynet address (§3.2).
#[must_use]
pub fn group_ipv6(address: Ipv6Addr) -> Ipv6Addr {
    Ipv6Addr::from(group_bytes(address.octets()))
}

/// Derives the immutable lowercase base32 identity label from section 7.1.
pub fn identity_label(identity: &Identity) -> Result<String, DerivationError> {
    let digest = identity_digest(identity)?;
    let mut label = String::with_capacity(20);
    for character_index in 0..20 {
        let mut value = 0_u8;
        for bit_index in 0..5 {
            let input_bit = character_index * 5 + bit_index;
            let bit = if input_bit < 96 {
                (digest[input_bit / 8] >> (7 - input_bit % 8)) & 1
            } else {
                0
            };
            value = (value << 1) | bit;
        }
        label.push(char::from(BASE32[usize::from(value)]));
    }
    Ok(label)
}

/// An address group together with its network and cryptographic owner (§3.4).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupOwner {
    /// The network that owns the group.
    pub network_id: NetworkId,
    /// The full identity that owns the group.
    pub identity: Identity,
    /// The normalized two-address group owned by the identity.
    pub group: AddressGroup,
}
/// A collision report identifying the already-configured owner (§3.4).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupConflict {
    /// The owner whose group conflicts with the candidate.
    pub conflicting_owner: GroupOwner,
}

/// Compares a candidate owner to every supplied owner for a group collision (§3.4).
///
/// When `allow_idempotent_owner` is true, the exact network-and-identity owner is skipped.
#[must_use]
pub fn compare_group_owners(
    candidate: GroupOwner,
    existing: &[GroupOwner],
    allow_idempotent_owner: bool,
) -> Option<GroupConflict> {
    for owner in existing {
        if candidate.group != owner.group {
            continue;
        }
        let idempotent = allow_idempotent_owner
            && candidate.network_id == owner.network_id
            && candidate.identity == owner.identity;
        if !idempotent {
            return Some(GroupConflict {
                conflicting_owner: *owner,
            });
        }
    }
    None
}
/// Checks a peer against all local and peer groups before installation (§3.4).
pub fn check_peer_group(
    candidate: GroupOwner,
    local_groups: &[GroupOwner],
    peer_groups: &[GroupOwner],
) -> Result<(), GroupConflict> {
    if let Some(conflict) = compare_group_owners(candidate, local_groups, false) {
        return Err(conflict);
    }
    if let Some(conflict) = compare_group_owners(candidate, peer_groups, true) {
        return Err(conflict);
    }
    Ok(())
}
/// Checks a newly joined local network group against every existing owner (§3.4).
pub fn check_new_local_group(
    candidate: GroupOwner,
    local_groups: &[GroupOwner],
    peer_groups: &[GroupOwner],
) -> Result<(), GroupConflict> {
    if let Some(conflict) = compare_group_owners(candidate, local_groups, false) {
        return Err(conflict);
    }
    if let Some(conflict) = compare_group_owners(candidate, peer_groups, false) {
        return Err(conflict);
    }
    Ok(())
}

fn n4_bytes_from_group(mut group: [u8; 16]) -> [u8; 16] {
    group[15] |= 1;
    group
}
fn address_digest(input: &[u8]) -> Result<[u8; ADDRESS_DIGEST_BYTES], DerivationError> {
    let mut hasher = <Blake2sMac<U15> as KeyInit>::new_from_slice(ADDRESS_KEY)
        .map_err(|_| DerivationError::InvalidOutputSize)?;
    hasher.update(input);
    let digest = hasher.finalize().into_bytes();
    let mut output = [0_u8; ADDRESS_DIGEST_BYTES];
    output.copy_from_slice(&digest);
    Ok(output)
}

fn identity_digest(input: &[u8]) -> Result<[u8; IDENTITY_DIGEST_BYTES], DerivationError> {
    let mut hasher = <Blake2sMac<U12> as KeyInit>::new_from_slice(IDENTITY_KEY)
        .map_err(|_| DerivationError::InvalidOutputSize)?;
    hasher.update(input);
    let digest = hasher.finalize().into_bytes();
    let mut output = [0_u8; IDENTITY_DIGEST_BYTES];
    output.copy_from_slice(&digest);
    Ok(output)
}
