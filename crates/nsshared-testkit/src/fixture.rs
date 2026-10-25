//! Seeded Ed25519 fixture authorities. Fixture keys are labelled test inputs, never
//! producer keys.

use ed25519_dalek::{Signer, SigningKey};
use nsshared_identity::keys::IdentityKey;

/// The signing key whose 32-byte seed repeats `seed`.
#[must_use]
pub fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// The identity key of [`signing_key`]`(seed)`.
#[must_use]
pub fn identity(seed: u8) -> IdentityKey {
    IdentityKey::from_bytes(&signing_key(seed).verifying_key().to_bytes()).unwrap()
}

/// The identity key encoded by lowercase hex text of 32 bytes.
#[must_use]
pub fn identity_hex(text: &str) -> IdentityKey {
    IdentityKey::try_from(crate::hex::unhex(text).as_slice()).unwrap()
}

/// The signature of `message` by [`signing_key`]`(seed)`.
#[must_use]
pub fn sign(seed: u8, message: &[u8]) -> [u8; 64] {
    signing_key(seed).sign(message).to_bytes()
}
