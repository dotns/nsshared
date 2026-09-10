use control::mesh::{self, WssFrame, WssHello};
use ed25519_dalek::{Signature, VerifyingKey};

#[path = "fixtures/mesh-wss-v1/oracle.rs"]
mod oracle;

fn vectors() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/mesh-wss-v1/vectors.json")).unwrap()
}

fn bytes(vector: &serde_json::Value, field: &str) -> Vec<u8> {
    hex::decode(vector[field].as_str().unwrap()).unwrap()
}

#[test]
fn mesh_wss_preauth_independent_oracle_matches_fixed_binary_messages() {
    assert_eq!(oracle::vectors(), vectors());
}

#[test]
fn mesh_wss_preauth_hello_matches_separate_message_and_original_signature_domain() {
    for vector in vectors()["vectors"].as_array().unwrap() {
        let challenge = bytes(vector, "challenge_hex");
        let wire = bytes(vector, "hello_hex");
        let input = bytes(vector, "signing_input_hex");
        assert_eq!(challenge.len(), 32);
        let hello = WssHello::decode(&wire).unwrap();
        assert_eq!(hello.challenge.as_slice(), challenge);
        assert_eq!(hello.origin, vector["origin"].as_str().unwrap());
        assert_eq!(hello.signer_pub.as_slice(), bytes(vector, "signer_hex"));
        assert_eq!(hello.wg_pub.as_slice(), bytes(vector, "wg_hex"));
        assert_eq!(hello.encode().unwrap(), wire);
        assert_eq!(hello.signing_input().unwrap(), input);
        VerifyingKey::from_bytes(&hello.signer_pub)
            .unwrap()
            .verify_strict(&input, &Signature::from_bytes(&hello.signature))
            .unwrap();
        let mut wrong_domain = input;
        wrong_domain[0] ^= 1;
        assert!(
            VerifyingKey::from_bytes(&hello.signer_pub)
                .unwrap()
                .verify_strict(&wrong_domain, &Signature::from_bytes(&hello.signature))
                .is_err()
        );
        assert!(mesh::decode_wss(&wire, 1500).is_err());
    }
    // Random challenge bytes can look like authenticated framing. The connection
    // phase, not a decoder fallback, decides what the first binary message means.
    let fixture = vectors();
    let challenge = bytes(&fixture["vectors"][1], "challenge_hex");
    assert_eq!(
        mesh::decode_wss(&challenge, 1500).unwrap(),
        WssFrame::Control(&challenge[2..])
    );
}

#[test]
fn mesh_wss_preauth_hello_rejects_wrappers_coalescing_and_ambiguous_payloads() {
    for vector in vectors()["vectors"].as_array().unwrap() {
        let wire = bytes(vector, "hello_hex");
        let challenge = bytes(vector, "challenge_hex");
        for prefix in [&[1, 1][..], mesh::UDP_MAGIC, &challenge] {
            let mut wrapped = prefix.to_vec();
            wrapped.extend_from_slice(&wire);
            assert!(WssHello::decode(&wrapped).is_err());
        }
        for len in 0..wire.len() {
            assert!(WssHello::decode(&wire[..len]).is_err());
        }
        let mut coalesced = wire.clone();
        coalesced.extend_from_slice(&wire);
        assert!(WssHello::decode(&coalesced).is_err());
        let mut duplicate = wire.clone();
        assert_eq!(duplicate[0], 0xa6);
        duplicate[0] = 0xa7;
        duplicate.extend_from_slice(&[0, 1]);
        assert!(WssHello::decode(&duplicate).is_err());
        let mut version = wire.clone();
        version[2] = 2;
        assert!(WssHello::decode(&version).is_err());
        assert!(WssHello::decode(&challenge).is_err());
    }
}
