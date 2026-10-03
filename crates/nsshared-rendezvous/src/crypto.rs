//! Shared primitives: SHA-256, keyed BLAKE2s, HKDF-SHA256, X25519 and strict Ed25519
//! (rendezvous §4, quick-v2 §10.2, §12.2).

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
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

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

/// The requested HKDF output exceeds 255 SHA-256 blocks (RFC 5869 §2.3).
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("HKDF output is too long")]
pub(crate) struct HkdfLength;

/// HKDF-SHA256 with a zero-length salt over `ikm`, `info` being the concatenation of
/// `info_parts`, filling `out` (same as the nsshared-wire relay session key, quick-v2 §8.3).
///
/// # Errors
///
/// [`HkdfLength`] when `out` is longer than 8160 bytes; `out` is then zeroed.
pub(crate) fn hkdf_sha256(
    ikm: &[u8],
    info_parts: &[&[u8]],
    out: &mut [u8],
) -> Result<(), HkdfLength> {
    hkdf_sha256_salted(&[], ikm, info_parts, out)
}

fn hkdf_sha256_salted(
    salt: &[u8],
    ikm: &[u8],
    info_parts: &[&[u8]],
    out: &mut [u8],
) -> Result<(), HkdfLength> {
    let result = Hkdf::<Sha256>::new(Some(salt), ikm).expand_multi_info(info_parts, out);
    if result.is_err() {
        out.zeroize();
        return Err(HkdfLength);
    }
    Ok(())
}

/// X25519 produced the all-zero shared secret (a small-order public key).
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("X25519 shared secret is all zero")]
pub(crate) struct AllZeroSharedSecret;

/// X25519(`secret`, `public`) (RFC 7748 §5), rejecting the all-zero result.
///
/// # Errors
///
/// [`AllZeroSharedSecret`] for a small-order `public`.
pub(crate) fn x25519(
    secret: &[u8; 32],
    public: &[u8; 32],
) -> Result<[u8; 32], AllZeroSharedSecret> {
    let shared = StaticSecret::from(*secret).diffie_hellman(&PublicKey::from(*public));
    if shared.was_contributory() {
        Ok(*shared.as_bytes())
    } else {
        Err(AllZeroSharedSecret)
    }
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
    fn blake2s_keyed_matches_the_nsshared_wire_node_id() {
        let identity = [9; 32];
        let derived: [u8; 12] = blake2s_keyed(
            nsshared_wire::NODE_ID_LABEL,
            &[&identity[..16], &identity[16..]],
        );
        assert_eq!(
            &derived,
            nsshared_wire::NodeId::derive(&identity).as_bytes()
        );
        // An over-long key never panics.
        assert_eq!(blake2s_keyed::<4>(&[1; 33], &[b"x"]), [0; 4]);
    }

    #[test]
    fn hkdf_rfc5869_test_cases_1_and_3() {
        let ikm = [0x0b; 22];
        let mut okm = [0; 42];
        hkdf_sha256_salted(
            &hex::<13>("000102030405060708090a0b0c"),
            &ikm,
            &[&hex::<4>("f0f1f2f3"), &hex::<6>("f4f5f6f7f8f9")],
            &mut okm,
        )
        .unwrap();
        assert_eq!(
            okm,
            hex::<42>(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            )
        );
        hkdf_sha256(&ikm, &[], &mut okm).unwrap();
        assert_eq!(
            okm,
            hex::<42>(
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
            )
        );
        let mut long = vec![1; 255 * 32 + 1];
        assert_eq!(hkdf_sha256(&ikm, &[], &mut long), Err(HkdfLength));
        assert!(long.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn x25519_rfc7748_section_6_1() {
        let alice = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_public = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let bob = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let bob_public = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let shared = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(x25519(&alice, &bob_public), Ok(shared));
        assert_eq!(x25519(&bob, &alice_public), Ok(shared));
    }

    #[test]
    fn x25519_rejects_a_small_order_public_key() {
        assert_eq!(x25519(&[7; 32], &[0; 32]), Err(AllZeroSharedSecret));
        let mut one = [0; 32];
        one[0] = 1;
        assert_eq!(x25519(&[7; 32], &one), Err(AllZeroSharedSecret));
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
