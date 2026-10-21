//! Membership realm identity, without clock, authority or namespace inference.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::{fmt, fmt::Write as _, str::FromStr};
use thiserror::Error;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Unsigned big-endian ULID value; every 128-bit value is valid.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RealmId([u8; 16]);

/// Text is not the unique canonical uppercase 26-character ULID spelling.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("noncanonical realm identity")]
pub struct RealmIdError;

impl RealmId {
    /// Preserves all 16 bytes without timestamp interpretation.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Exact unsigned big-endian representation for existing binary wire positions.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Exact unsigned big-endian representation.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }
}

impl FromStr for RealmId {
    type Err = RealmIdError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let bytes = text.as_bytes();
        if bytes.len() != 26 || !(b'0'..=b'7').contains(&bytes[0]) {
            return Err(RealmIdError);
        }
        let mut value = 0u128;
        for byte in bytes {
            let digit = ALPHABET
                .iter()
                .position(|candidate| candidate == byte)
                .ok_or(RealmIdError)?;
            value = (value << 5) | digit as u128;
        }
        Ok(Self(value.to_be_bytes()))
    }
}

impl fmt::Display for RealmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = u128::from_be_bytes(self.0);
        for shift in (0..26).rev().map(|index| index * 5) {
            f.write_char(char::from(ALPHABET[((value >> shift) & 31) as usize]))?;
        }
        Ok(())
    }
}

impl From<[u8; 16]> for RealmId {
    fn from(bytes: [u8; 16]) -> Self {
        Self::from_bytes(bytes)
    }
}
impl From<RealmId> for [u8; 16] {
    fn from(realm: RealmId) -> Self {
        realm.to_bytes()
    }
}

// Serde is used for text positions only; binary CBOR owners write as_bytes().
impl Serialize for RealmId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}
impl<'de> Deserialize<'de> for RealmId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Text;
        impl de::Visitor<'_> for Text {
            type Value = RealmId;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("canonical uppercase 26-character realm identity")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<RealmId, E> {
                value.parse().map_err(E::custom)
            }
        }
        deserializer.deserialize_str(Text)
    }
}
