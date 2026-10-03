//! Local IPv4 alias candidates (quick-v2 §2.2, §6.2).

use crate::constants::{
    ALIAS_CANDIDATES, ALIAS_KIND_IPV4, ALIAS_KIND_IPV6, ALIAS4_LABEL, DEFAULT_ALIAS_POOL_BASE,
    DEFAULT_ALIAS_POOL_PREFIX_LEN,
};
use crate::identity::{Identity, keyed_blake2s};
use blake2::digest::consts::U3;
use std::net::Ipv4Addr;
use thiserror::Error;

/// A rejected alias derivation, pool or selection (quick-v2 §6.2).
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AliasError {
    /// The kind is neither 6 (native IPv6 service) nor 4 (IPv4 service).
    #[error("alias kind must be 4 or 6, got {0}")]
    InvalidKind(u8),
    /// The candidate index is outside `0..16`.
    #[error("alias candidate index must be below 16, got {0}")]
    InvalidIndex(u8),
    /// The pool prefix length exceeds 32.
    #[error("alias pool prefix length must be at most 32, got {0}")]
    PrefixOutOfRange(u8),
    /// The pool base has host bits set for its prefix length.
    #[error("alias pool base {base} is not aligned to /{prefix_len}")]
    MisalignedBase {
        /// The configured base.
        base: Ipv4Addr,
        /// The configured prefix length.
        prefix_len: u8,
    },
    /// All 16 candidates are unavailable.
    #[error("all 16 alias candidates are unavailable")]
    Exhausted,
}

/// A validated IPv4 alias pool `base/prefix_len`, default `100.64.0.0/10` (quick-v2 §6.2).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AliasPool {
    base: Ipv4Addr,
    prefix_len: u8,
}

impl AliasPool {
    /// Validates a pool: `prefix_len` at most 32 and `base` aligned to it (quick-v2 §6.2).
    ///
    /// # Errors
    ///
    /// [`AliasError::PrefixOutOfRange`] or [`AliasError::MisalignedBase`].
    pub fn new(base: Ipv4Addr, prefix_len: u8) -> Result<Self, AliasError> {
        if prefix_len > 32 {
            return Err(AliasError::PrefixOutOfRange(prefix_len));
        }
        let host_mask = u32::MAX.checked_shr(u32::from(prefix_len)).unwrap_or(0);
        if base.to_bits() & host_mask != 0 {
            return Err(AliasError::MisalignedBase { base, prefix_len });
        }
        Ok(Self { base, prefix_len })
    }

    /// Returns the first pool address (quick-v2 §6.2).
    #[must_use]
    pub const fn base(&self) -> Ipv4Addr {
        self.base
    }

    /// Returns the pool prefix length (quick-v2 §6.2).
    #[must_use]
    pub const fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Returns the number of addresses in the pool, `2^(32 - prefix_len)` (quick-v2 §6.2).
    #[must_use]
    pub const fn size(&self) -> u64 {
        1_u64 << (32 - self.prefix_len)
    }
}

impl Default for AliasPool {
    fn default() -> Self {
        Self {
            base: DEFAULT_ALIAS_POOL_BASE,
            prefix_len: DEFAULT_ALIAS_POOL_PREFIX_LEN,
        }
    }
}

/// `H22(I, kind, i)`: the high 22 bits of `BLAKE2s(out = 3, key = "ns-alias4-v2")(I ‖ kind ‖ i)`
/// (quick-v2 §2.2).
///
/// # Errors
///
/// [`AliasError::InvalidKind`] unless `kind` is 4 or 6; [`AliasError::InvalidIndex`] unless
/// `index < 16`.
pub fn alias_h22(identity: &Identity, kind: u8, index: u8) -> Result<u32, AliasError> {
    if kind != ALIAS_KIND_IPV4 && kind != ALIAS_KIND_IPV6 {
        return Err(AliasError::InvalidKind(kind));
    }
    if index >= ALIAS_CANDIDATES {
        return Err(AliasError::InvalidIndex(index));
    }
    let digest: [u8; 3] = keyed_blake2s::<U3>(ALIAS4_LABEL, &[identity, &[kind, index]]).into();
    let [high, middle, low] = digest;
    Ok(u32::from_be_bytes([0, high, middle, low]) >> 2)
}

/// Candidate `i`: `pool.base + (H22(I, kind, i) mod pool.size)` (quick-v2 §6.2).
///
/// # Errors
///
/// As [`alias_h22`].
pub fn alias_candidate(
    identity: &Identity,
    kind: u8,
    index: u8,
    pool: &AliasPool,
) -> Result<Ipv4Addr, AliasError> {
    let offset = u64::from(alias_h22(identity, kind, index)?) % pool.size();
    // The base is aligned and `offset < size`, so the sum stays inside the pool.
    let offset = u32::try_from(offset).unwrap_or(0);
    Ok(Ipv4Addr::from_bits(pool.base.to_bits() | offset))
}

/// The 16 alias candidates of `(I, kind)` in sequence order (quick-v2 §6.2).
///
/// # Errors
///
/// [`AliasError::InvalidKind`] unless `kind` is 4 or 6.
pub fn alias_candidates(
    identity: &Identity,
    kind: u8,
    pool: &AliasPool,
) -> Result<[Ipv4Addr; ALIAS_CANDIDATES as usize], AliasError> {
    let mut candidates = [Ipv4Addr::UNSPECIFIED; ALIAS_CANDIDATES as usize];
    for (index, candidate) in (0..ALIAS_CANDIDATES).zip(candidates.iter_mut()) {
        *candidate = alias_candidate(identity, kind, index, pool)?;
    }
    Ok(candidates)
}

/// Selects the first usable alias candidate, skipping `self4` and every address for which
/// `unavailable` returns true (table entries, host routes, interface addresses and firewall
/// rules known to the caller) (quick-v2 §6.2).
///
/// # Errors
///
/// [`AliasError::InvalidKind`] unless `kind` is 4 or 6; [`AliasError::Exhausted`] when all
/// 16 candidates are unusable.
pub fn select_alias(
    identity: &Identity,
    kind: u8,
    pool: &AliasPool,
    self4: Ipv4Addr,
    mut unavailable: impl FnMut(Ipv4Addr) -> bool,
) -> Result<Ipv4Addr, AliasError> {
    alias_candidates(identity, kind, pool)?
        .into_iter()
        .find(|&candidate| candidate != self4 && !unavailable(candidate))
        .ok_or(AliasError::Exhausted)
}
