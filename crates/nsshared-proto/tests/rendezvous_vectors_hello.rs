//! Generated actor `hello` vectors (rendezvous §3, §4; quick-v2 §12.2).

#![allow(clippy::unwrap_used, clippy::panic, reason = "test fixture helpers")]

mod support;

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use nsshared_proto::RelayId;
use nsshared_proto::rendezvous::{
    auth::{ACTOR_CONTEXT, AuthError, Hello},
    transport::{self, Request},
};
use support::vectors::load;

#[test]
fn hello_signatures_match_vectors() {
    let vectors = load("hello");
    let mut positives = 0;
    for v in vectors.iter().filter(|v| !v.is_reject()) {
        positives += 1;
        let name = v.name();
        let key = SigningKey::from_bytes(&v.hex_array("actor_seed"));
        let nonce = v.hex_array::<32>("nonce");
        let authority = RelayId::parse(v.get("authority")).unwrap();

        let message = [ACTOR_CONTEXT, &nonce, v.get("authority").as_bytes()].concat();
        assert_eq!(message, v.hex("message"), "{name}");
        VerifyingKey::from_bytes(&v.hex_array("actor"))
            .unwrap()
            .verify_strict(&message, &Signature::from_bytes(&v.hex_array("signature")))
            .unwrap();

        // Encode equals the fixture.
        let hello = Hello::sign(&key, &nonce, &authority);
        assert_eq!(hello.actor, v.hex_array::<32>("actor"), "{name}");
        assert_eq!(hello.signature, v.hex_array::<64>("signature"), "{name}");
        hello.verify(&nonce, &authority).unwrap();
        let request = Request::Hello(hello);
        assert_eq!(
            transport::encode_request(&request).unwrap(),
            v.get("request"),
            "{name}"
        );

        // Decode then re-encode equals the fixture.
        let decoded = transport::decode_request(v.get("request")).unwrap();
        assert_eq!(decoded, request, "{name}");
        assert_eq!(
            transport::encode_request(&decoded).unwrap(),
            v.get("request")
        );
    }
    assert!(positives >= 2);
}

#[test]
fn rejected_hellos_match_vectors() {
    let vectors = load("hello");
    let mut negatives = 0;
    for v in vectors.iter().filter(|v| v.is_reject()) {
        negatives += 1;
        assert_eq!(v.reason(), "invalid_signature", "{}", v.name());
        let hello = Hello {
            actor: v.hex_array("actor"),
            signature: v.hex_array("signature"),
        };
        let authority = RelayId::parse(v.get("authority")).unwrap();
        assert_eq!(
            hello.verify(&v.hex_array("nonce"), &authority),
            Err(AuthError::InvalidSignature),
            "{}",
            v.name()
        );
    }
    assert!(negatives >= 5);
}
