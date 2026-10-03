//! Typed identity and session keys with their canonical encodings (quick-v2 §2.1, §2.3).
//!
//! | Type | Key | Binary | Canonical text |
//! | --- | --- | --- | --- |
//! | [`IdentityKey`] | Ed25519 identity public key `I` | 32 bytes, a valid Ed25519 point encoding | unpadded base64url, 43 characters |
//! | [`IdentitySecret`] | Ed25519 secret seed | 32 bytes, [`IdentitySecret::expose_seed`] | unpadded base64url, [`IdentitySecret::to_secret_text`] |
//! | [`WgSessionKey`] | X25519 WireGuard public key `K` | 32 bytes | padded standard base64, 44 characters, as `wg` prints it |
//! | [`WgSessionSecret`] | X25519 WireGuard private key | 32 bytes, [`WgSessionSecret::expose_bytes`] | padded standard base64, [`WgSessionSecret::to_secret_text`] |
//!
//! Text parsing is strict: the wrong alphabet, wrong padding, wrong length and
//! non-canonical trailing bits are rejected, so every key has exactly one text form.
//! Secrets have no `Display`, print a redacted `Debug` and are zeroized on drop.
//!
//! The WireGuard types carry a `Wg` prefix because [`SessionKey`](crate::SessionKey) already
//! names the relay session key `sk` (quick-v2 §8.3).
//!
//! # Replaces in ns
//!
//! Compared with ns `crates/overlay/src/identity.rs` (`NodeIdentity`), which wraps a raw
//! [`Identity`] and caches its [`GroupOwner`] and [`NodeId`]:
//!
//! | ns helper | Replacement |
//! | --- | --- |
//! | `NodeIdentity::new(identity)` | [`IdentityKey::from_bytes`] / [`IdentityKey::try_from`]; derivations are recomputed on demand instead of cached. A node that wants the cache keeps a thin ns wrapper. |
//! | `NodeIdentity::identity` | [`IdentityKey::as_bytes`], `Identity::from(key)` |
//! | `NodeIdentity::node_id` | [`IdentityKey::node_id`] |
//! | `NodeIdentity::group` | [`IdentityKey::address_group`] |
//! | `NodeIdentity::owner` | [`IdentityKey::group_owner`] |
//! | `NodeIdentity::n6` | [`IdentityKey::node6`] |
//! | `NodeIdentity::n4` | [`IdentityKey::node4`] |
//! | `NodeIdentity::alias_candidates` | [`IdentityKey::alias_candidates`] |
//! | `NodeIdentity::select_alias` | [`IdentityKey::select_alias`] |
//! | `NodeIdentity::lan6` | [`IdentityKey::lan6`] |
//! | `NodeIdentity::check_peer` | Stays ns-specific: it checks against the node's own cached [`GroupOwner`] and its peer table; the primitive is [`check_address_conflict`](crate::check_address_conflict) with [`IdentityKey::group_owner`]. |
//! | `ed25519_dalek::SigningKey` held directly (registry, relay client and session) and built with `SigningKey::from_bytes` | [`IdentitySecret::from_seed`] / [`IdentitySecret::generate`], passed to the signing APIs through [`IdentitySecret::signing_key`] |
//!
//! ns has no base64 key text or key generation helpers in its overlay crate; the
//! [`IdentityKey`] / [`WgSessionKey`] `Display` and `FromStr` forms and the secret text
//! methods are the shared encodings for configuration and display.

use crate::{
    alias::{AliasError, AliasPool, alias_candidates, select_alias},
    constants::ALIAS_CANDIDATES,
    identity::{AddressGroup, GroupOwner, Identity, NodeId},
    lan::Lan6Prefix,
    record::WireGuardKey,
};
use base64::{
    DecodeError, DecodeSliceError, Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// Length of every key in bytes.
pub const KEY_BYTES: usize = 32;

/// Length of the unpadded base64url text of an identity key or secret, 43 characters.
pub const IDENTITY_KEY_TEXT_LEN: usize = 43;

/// Length of the padded standard base64 text of a session key or secret, 44 characters.
pub const WG_SESSION_KEY_TEXT_LEN: usize = 44;

/// A rejected binary or text key encoding.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum KeyParseError {
    /// The binary form is not exactly 32 bytes.
    #[error("key must be {KEY_BYTES} bytes, got {0}")]
    ByteLength(usize),
    /// The text form has the wrong length.
    #[error("key text must be {expected} characters, got {actual} bytes")]
    TextLength {
        /// The required length.
        expected: usize,
        /// The length of the rejected text in bytes.
        actual: usize,
    },
    /// The text has missing, misplaced or (for base64url) any `=` padding.
    #[error("key text has invalid padding")]
    Padding,
    /// The text contains a byte outside the expected base64 alphabet.
    #[error("key text contains invalid byte {byte:#04x} at offset {offset}")]
    InvalidCharacter {
        /// Offset of the byte in the text.
        offset: usize,
        /// The rejected byte.
        byte: u8,
    },
    /// The last symbol carries non-zero bits beyond the 32 key bytes.
    #[error("key text has non-zero trailing bits")]
    NonCanonicalTrailingBits,
    /// The bytes are not a valid Ed25519 public key encoding.
    #[error("bytes are not a valid Ed25519 public key")]
    InvalidIdentityKey,
}

/// The OS random source failed while generating a secret.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("OS random source failed: {0}")]
pub struct KeyGenerationError(getrandom::Error);

/// Copies a 32-byte slice, rejecting any other length.
fn array_from_slice(bytes: &[u8]) -> Result<[u8; KEY_BYTES], KeyParseError> {
    <[u8; KEY_BYTES]>::try_from(bytes).map_err(|_| KeyParseError::ByteLength(bytes.len()))
}

/// Strictly decodes `text` of exactly `text_len` characters into `out`.
fn decode_text(
    engine: &impl Engine,
    text: &str,
    text_len: usize,
    out: &mut [u8; KEY_BYTES],
) -> Result<(), KeyParseError> {
    if text.len() != text_len {
        return Err(KeyParseError::TextLength {
            expected: text_len,
            actual: text.len(),
        });
    }
    match engine.decode_slice(text, out) {
        Ok(KEY_BYTES) => Ok(()),
        Ok(_) | Err(DecodeSliceError::OutputSliceTooSmall) => Err(KeyParseError::TextLength {
            expected: text_len,
            actual: text.len(),
        }),
        Err(DecodeSliceError::DecodeError(error)) => Err(match error {
            DecodeError::InvalidByte(_, b'=') | DecodeError::InvalidPadding => {
                KeyParseError::Padding
            }
            DecodeError::InvalidByte(offset, byte) => {
                KeyParseError::InvalidCharacter { offset, byte }
            }
            DecodeError::InvalidLength(_) => KeyParseError::TextLength {
                expected: text_len,
                actual: text.len(),
            },
            DecodeError::InvalidLastSymbol { .. } => KeyParseError::NonCanonicalTrailingBits,
        }),
    }
}

/// Decodes unpadded base64url, rejecting any `=` before the length check.
fn decode_url_text(text: &str, out: &mut [u8; KEY_BYTES]) -> Result<(), KeyParseError> {
    if text.contains('=') {
        return Err(KeyParseError::Padding);
    }
    decode_text(&URL_SAFE_NO_PAD, text, IDENTITY_KEY_TEXT_LEN, out)
}

/// Decodes padded standard base64 as printed by `wg`, requiring the final `=`.
fn decode_standard_text(text: &str, out: &mut [u8; KEY_BYTES]) -> Result<(), KeyParseError> {
    if text.len() == WG_SESSION_KEY_TEXT_LEN && !text.ends_with('=') {
        return Err(KeyParseError::Padding);
    }
    decode_text(&STANDARD, text, WG_SESSION_KEY_TEXT_LEN, out)
}

/// Fills a 32-byte buffer from the OS random source.
fn random_bytes() -> Result<Zeroizing<[u8; KEY_BYTES]>, KeyGenerationError> {
    let mut bytes = Zeroizing::new([0_u8; KEY_BYTES]);
    getrandom::fill(bytes.as_mut_slice()).map_err(KeyGenerationError)?;
    Ok(bytes)
}

/// The Ed25519 identity public key `I` (quick-v2 §2.1).
///
/// Always holds a valid Ed25519 point encoding. Text form is unpadded RFC 4648
/// base64url, 43 characters (quick-v2 §2.3).
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IdentityKey(Identity);

impl IdentityKey {
    /// Validates raw identity bytes as an Ed25519 public key.
    ///
    /// # Errors
    ///
    /// [`KeyParseError::InvalidIdentityKey`] when the bytes do not decode to a point.
    pub fn from_bytes(bytes: &Identity) -> Result<Self, KeyParseError> {
        VerifyingKey::from_bytes(bytes).map_err(|_| KeyParseError::InvalidIdentityKey)?;
        Ok(Self(*bytes))
    }

    /// Returns the raw 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &Identity {
        &self.0
    }

    /// Returns a copy of the raw 32 bytes.
    #[must_use]
    pub const fn to_bytes(&self) -> Identity {
        self.0
    }

    /// Returns the node ID (quick-v2 §2.2).
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        NodeId::derive(&self.0)
    }

    /// Returns the `/127` address group (quick-v2 §2.2).
    #[must_use]
    pub fn address_group(&self) -> AddressGroup {
        AddressGroup::derive(&self.0)
    }

    /// Returns the identity with its address group, as kept in a peer table (quick-v2 §2.2).
    #[must_use]
    pub fn group_owner(&self) -> GroupOwner {
        GroupOwner::derive(&self.0)
    }

    /// Returns the native IPv6 service address `N6` (quick-v2 §2.2).
    #[must_use]
    pub fn node6(&self) -> Ipv6Addr {
        self.address_group().n6()
    }

    /// Returns the IPv4 service address `N4` (quick-v2 §2.2).
    #[must_use]
    pub fn node4(&self) -> Ipv6Addr {
        self.address_group().n4()
    }

    /// Returns the published LAN prefix `lan6(I, subnet_id)/96` (next §4.1).
    #[must_use]
    pub fn lan6(&self, subnet_id: u16) -> Lan6Prefix {
        Lan6Prefix::derive(&self.0, subnet_id)
    }

    /// Returns the 16 IPv4 alias candidates for `kind` in sequence order (quick-v2 §6.2).
    ///
    /// # Errors
    ///
    /// As [`alias_candidates`].
    pub fn alias_candidates(
        &self,
        kind: u8,
        pool: &AliasPool,
    ) -> Result<[Ipv4Addr; ALIAS_CANDIDATES as usize], AliasError> {
        alias_candidates(&self.0, kind, pool)
    }

    /// Selects the first usable alias candidate (quick-v2 §6.2).
    ///
    /// # Errors
    ///
    /// As [`select_alias`].
    pub fn select_alias(
        &self,
        kind: u8,
        pool: &AliasPool,
        self4: Ipv4Addr,
        unavailable: impl FnMut(Ipv4Addr) -> bool,
    ) -> Result<Ipv4Addr, AliasError> {
        select_alias(&self.0, kind, pool, self4, unavailable)
    }
}

impl TryFrom<Identity> for IdentityKey {
    type Error = KeyParseError;

    fn try_from(bytes: Identity) -> Result<Self, Self::Error> {
        Self::from_bytes(&bytes)
    }
}

impl TryFrom<&[u8]> for IdentityKey {
    type Error = KeyParseError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(&array_from_slice(bytes)?)
    }
}

impl From<IdentityKey> for Identity {
    fn from(key: IdentityKey) -> Self {
        key.0
    }
}

impl fmt::Display for IdentityKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&URL_SAFE_NO_PAD.encode(self.0))
    }
}

impl fmt::Debug for IdentityKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IdentityKey({self})")
    }
}

impl FromStr for IdentityKey {
    type Err = KeyParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0_u8; KEY_BYTES];
        decode_url_text(text, &mut bytes)?;
        Self::from_bytes(&bytes)
    }
}

/// The Ed25519 identity secret, a 32-byte seed (quick-v2 §2.1).
///
/// No `Display` and no `Copy`; `Debug` is redacted and the seed is zeroized on drop.
#[derive(Clone)]
pub struct IdentitySecret(SigningKey);

impl IdentitySecret {
    /// Generates a secret from the OS random source.
    ///
    /// # Errors
    ///
    /// [`KeyGenerationError`] when the OS random source fails.
    pub fn generate() -> Result<Self, KeyGenerationError> {
        Ok(Self(SigningKey::from_bytes(&*random_bytes()?)))
    }

    /// Builds a secret from its 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: [u8; KEY_BYTES]) -> Self {
        let seed = Zeroizing::new(seed);
        Self(SigningKey::from_bytes(&seed))
    }

    /// Returns the public identity key `I`.
    #[must_use]
    pub fn public(&self) -> IdentityKey {
        IdentityKey(self.0.verifying_key().to_bytes())
    }

    /// Returns the signing key for the record and relay signing APIs, without copying the seed.
    #[must_use]
    pub const fn signing_key(&self) -> &SigningKey {
        &self.0
    }

    /// Exposes the raw 32-byte seed, e.g. for persistence.
    #[must_use]
    pub fn expose_seed(&self) -> &[u8; KEY_BYTES] {
        self.0.as_bytes()
    }

    /// Returns the seed as unpadded base64url text for persistence.
    #[must_use]
    pub fn to_secret_text(&self) -> Zeroizing<String> {
        Zeroizing::new(URL_SAFE_NO_PAD.encode(self.0.as_bytes()))
    }

    /// Parses a seed from unpadded base64url text, as strictly as [`IdentityKey`] text.
    ///
    /// # Errors
    ///
    /// [`KeyParseError`] for any non-canonical text.
    pub fn from_secret_text(text: &str) -> Result<Self, KeyParseError> {
        let mut seed = Zeroizing::new([0_u8; KEY_BYTES]);
        decode_url_text(text, &mut seed)?;
        Ok(Self(SigningKey::from_bytes(&seed)))
    }
}

impl fmt::Debug for IdentitySecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IdentitySecret(<redacted>)")
    }
}

// The inner `SigningKey` zeroizes its seed on drop.
impl ZeroizeOnDrop for IdentitySecret {}

/// The X25519 WireGuard public key `K` (quick-v2 §2.1).
///
/// Any 32 bytes are accepted. Text form is padded RFC 4648 standard base64,
/// 44 characters, as the `wg` tool prints it (quick-v2 §2.3).
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WgSessionKey(WireGuardKey);

impl WgSessionKey {
    /// Wraps raw key bytes.
    #[must_use]
    pub const fn from_bytes(bytes: WireGuardKey) -> Self {
        Self(bytes)
    }

    /// Returns the raw 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &WireGuardKey {
        &self.0
    }

    /// Returns a copy of the raw 32 bytes.
    #[must_use]
    pub const fn to_bytes(&self) -> WireGuardKey {
        self.0
    }
}

impl From<WireGuardKey> for WgSessionKey {
    fn from(bytes: WireGuardKey) -> Self {
        Self(bytes)
    }
}

impl From<WgSessionKey> for WireGuardKey {
    fn from(key: WgSessionKey) -> Self {
        key.0
    }
}

impl TryFrom<&[u8]> for WgSessionKey {
    type Error = KeyParseError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        array_from_slice(bytes).map(Self)
    }
}

impl fmt::Display for WgSessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&STANDARD.encode(self.0))
    }
}

impl fmt::Debug for WgSessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WgSessionKey({self})")
    }
}

impl FromStr for WgSessionKey {
    type Err = KeyParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0_u8; KEY_BYTES];
        decode_standard_text(text, &mut bytes)?;
        Ok(Self(bytes))
    }
}

/// The X25519 WireGuard private key (quick-v2 §2.1).
///
/// Follows x25519-dalek `StaticSecret` semantics: the 32 bytes are stored and encoded
/// as given, and RFC 7748 clamping is applied only when the key is used, as `wg` does.
/// Unclamped bytes therefore round-trip unchanged and yield the same public key as
/// their clamped form. No `Display` and no `Copy`; `Debug` is redacted and the bytes are
/// zeroized on drop.
#[derive(Clone)]
pub struct WgSessionSecret(StaticSecret);

impl WgSessionSecret {
    /// Generates a secret from the OS random source.
    ///
    /// # Errors
    ///
    /// [`KeyGenerationError`] when the OS random source fails.
    pub fn generate() -> Result<Self, KeyGenerationError> {
        Ok(Self(StaticSecret::from(*random_bytes()?)))
    }

    /// Builds a secret from its 32 raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
        let bytes = Zeroizing::new(bytes);
        Self(StaticSecret::from(*bytes))
    }

    /// Returns the public WireGuard key `K`.
    #[must_use]
    pub fn public(&self) -> WgSessionKey {
        WgSessionKey(PublicKey::from(&self.0).to_bytes())
    }

    /// Exposes the raw 32 bytes, e.g. for persistence or a WireGuard device.
    #[must_use]
    pub fn expose_bytes(&self) -> &[u8; KEY_BYTES] {
        self.0.as_bytes()
    }

    /// Returns the key as padded standard base64 text, as `wg genkey` prints it.
    #[must_use]
    pub fn to_secret_text(&self) -> Zeroizing<String> {
        Zeroizing::new(STANDARD.encode(self.0.as_bytes()))
    }

    /// Parses a key from padded standard base64 text, as strictly as [`WgSessionKey`] text.
    ///
    /// # Errors
    ///
    /// [`KeyParseError`] for any non-canonical text.
    pub fn from_secret_text(text: &str) -> Result<Self, KeyParseError> {
        let mut bytes = Zeroizing::new([0_u8; KEY_BYTES]);
        decode_standard_text(text, &mut bytes)?;
        Ok(Self(StaticSecret::from(*bytes)))
    }
}

impl fmt::Debug for WgSessionSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WgSessionSecret(<redacted>)")
    }
}

// The inner `StaticSecret` zeroizes its bytes on drop.
impl ZeroizeOnDrop for WgSessionSecret {}
