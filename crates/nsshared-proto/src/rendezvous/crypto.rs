//! Rendezvous primitives: SHA-256, keyed BLAKE2s and strict Ed25519 (rendezvous §4,
//! quick-v2 §7.2, §12.2).

use blake2::{
    Blake2sMac,
    digest::{
        KeyInit, Mac,
        array::AssocArraySize,
        consts::U32,
        typenum::{IsLessOrEqual, True},
    },
};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// SHA-256 over the concatenation of `parts`.
pub(crate) fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Keyed BLAKE2s with an `N`-byte output over the concatenation of `parts`.
///
/// `key` must be at most 32 bytes (an empty key is unkeyed BLAKE2s); callers pass
/// constant labels. A longer key yields all zeros instead of a panic.
pub(crate) fn blake2s_keyed<const N: usize>(key: &[u8], parts: &[&[u8]]) -> [u8; N]
where
    [u8; N]: AssocArraySize,
    <[u8; N] as AssocArraySize>::Size: IsLessOrEqual<U32, Output = True>,
{
    let mut output = [0; N];
    let Ok(mut mac) =
        <Blake2sMac<<[u8; N] as AssocArraySize>::Size> as KeyInit>::new_from_slice(key)
    else {
        return output;
    };
    for part in parts {
        mac.update(part);
    }
    for (slot, byte) in output.iter_mut().zip(mac.finalize().into_bytes().iter()) {
        *slot = *byte;
    }
    output
}

/// Strict Ed25519 verification (RFC 8032 with canonical `S` and no small-order keys);
/// an invalid public key verifies nothing.
pub(crate) fn verify_strict(public: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(public)
        .and_then(|key| key.verify_strict(message, &Signature::from_bytes(signature)))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn hex<const N: usize>(text: &str) -> [u8; N] {
        let mut output = [0; N];
        for (index, slot) in output.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap();
        }
        output
    }

    #[test]
    fn sha256_concatenates_parts() {
        assert_eq!(
            sha256(&[b"a", b"bc"]),
            hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
    }

    #[test]
    fn blake2s_keyed_matches_the_node_id() {
        let identity = [9; 32];
        let derived: [u8; 12] =
            blake2s_keyed(crate::NODE_ID_LABEL, &[&identity[..16], &identity[16..]]);
        assert_eq!(&derived, crate::NodeId::derive(&identity).as_bytes());
        // An over-long key never panics.
        assert_eq!(blake2s_keyed::<4>(&[1; 33], &[b"x"]), [0; 4]);
    }

    #[test]
    fn verify_strict_accepts_only_valid_signatures() {
        let key = SigningKey::from_bytes(&[3; 32]);
        let public = key.verifying_key().to_bytes();
        let signature = key.sign(b"message").to_bytes();
        assert!(verify_strict(&public, b"message", &signature));
        assert!(!verify_strict(&public, b"other", &signature));
        // A point that does not decompress is an invalid key, not a panic.
        let invalid = (0..=u8::MAX)
            .map(|byte| [byte; 32])
            .find(|point| VerifyingKey::from_bytes(point).is_err())
            .unwrap();
        assert!(!verify_strict(&invalid, b"message", &signature));
        // The small-order identity point is rejected by strict verification.
        let mut identity = [0; 32];
        identity[0] = 1;
        assert!(!verify_strict(&identity, b"message", &signature));
    }
}
