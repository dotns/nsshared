//! The domain-separated Ed25519 signature rule shared by every signed account contract.

use ed25519_dalek::{Signature, VerifyingKey};
use nsshared_identity::keys::IdentityKey;

/// Why a signature check failed.
pub(in crate::account) enum SignatureFailure {
    /// The signer bytes are not a usable Ed25519 public key.
    Key,
    /// The signature does not verify strictly.
    Signature,
}

/// The input a signature covers: `domain` followed by the canonical signed bytes.
pub(in crate::account) fn signing_input(domain: &[u8], signed: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(domain.len() + signed.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(signed);
    input
}

/// Strictly verifies `signature` by `signer` over [`signing_input`]`(domain, signed)`.
pub(in crate::account) fn verify(
    signer: IdentityKey,
    domain: &[u8],
    signed: &[u8],
    signature: &[u8; 64],
) -> Result<(), SignatureFailure> {
    let key = VerifyingKey::from_bytes(signer.as_bytes()).map_err(|_| SignatureFailure::Key)?;
    key.verify_strict(
        &signing_input(domain, signed),
        &Signature::from_bytes(signature),
    )
    .map_err(|_| SignatureFailure::Signature)
}
